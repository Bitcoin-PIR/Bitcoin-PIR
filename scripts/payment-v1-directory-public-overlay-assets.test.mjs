import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  REVIEWED_SYSTEMD_VERSION,
  computeApprovedPlanSha256,
  renderBundle,
  verifyBundle,
} from "./payment-v1-rendered-artifact-gate.mjs";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const paths = Object.freeze({
  artifactGate: "scripts/payment-v1-directory-public-haproxy-artifact-gate.mjs",
  buildManifest:
    "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
  caddy:
    "deploy/payment-v1/edge/integrated-existing-bhtm-caddy-directory-public.managed.Caddyfile.in",
  dropin:
    "deploy/payment-v1/systemd/bhtm-caddy.directory-public-edge.conf.in",
  haproxy: "deploy/payment-v1/edge/directory-public-haproxy.cfg.in",
  readme: "deploy/payment-v1/edge/README.md",
  unit: "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
});

function read(name) {
  return readFileSync(join(REPOSITORY, paths[name]), "utf8");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function renderText(sourcePath, placeholders) {
  let text = readFileSync(join(REPOSITORY, sourcePath), "utf8");
  for (const [name, value] of Object.entries(placeholders)) {
    text = text.replaceAll(`@${name}@`, value);
  }
  assert.doesNotMatch(text, /@[A-Z][A-Z0-9_]+@/u);
  return text;
}

function withoutComments(text) {
  return text
    .split("\n")
    .map((line) => line.replace(/\s+#.*$/u, ""))
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
}

function commandFromEnvironment(name, candidates) {
  if (process.env[name] !== undefined) {
    assert.equal(process.env[name].startsWith("/"), true, `${name} must be absolute`);
    assert.equal(existsSync(process.env[name]), true, `${name} does not exist`);
    return process.env[name];
  }
  return candidates.find((candidate) => existsSync(candidate));
}

test("directory-public Caddy asset is a closed single read lane", () => {
  const caddy = withoutComments(read("caddy"));
  const placeholders = [...new Set(caddy.match(/@[A-Z0-9_]+@/gu) ?? [])].sort();
  assert.deepEqual(placeholders, ["@DIRECTORY_RELAY_WSS_HOST@", "@PUBLIC_HTTPS_BIND@"]);
  assert.equal(
    (caddy.match(/^@DIRECTORY_RELAY_WSS_HOST@ \{$/gmu) ?? []).length,
    1,
  );
  assert.equal((caddy.match(/^\s*reverse_proxy /gmu) ?? []).length, 1);
  assert.equal((caddy.match(/^\s*proxy_protocol v2$/gmu) ?? []).length, 1);
  assert.equal((caddy.match(/^\s*header_up -\*$/gmu) ?? []).length, 1);
  assert.match(
    caddy,
    /reverse_proxy unix\/\/run\/bitcoinpir-directory-public-edge\/directory-public\.sock/u,
  );
  assert.match(caddy, /expression \{http\.request\.uri\} == "\/"/u);
  assert.match(caddy, /^\s*respond "" 404$/mu);
  assert.match(caddy, /^\s*header_down -Set-Cookie$/mu);
  assert.doesNotMatch(
    caddy,
    /PROVIDER|ISSUER|PAYMENT|PUBLISHER|PRIVATE_BIND|CLIENT_IP|\/v1\/pir|\/v1\/quotes|header_up\s+(?:Authorization|Cookie|Forwarded|X-Forwarded-For)\b/iu,
  );
  assert.doesNotMatch(caddy, /^\s*(?:tls|import|invoke|log|route|handle_path)\b/mu);
});

test("directory-public HAProxy asset has one ephemeral source table and backend", () => {
  const haproxy = withoutComments(read("haproxy"));
  assert.equal((haproxy.match(/^frontend /gmu) ?? []).length, 1);
  assert.equal((haproxy.match(/^\s*bind .* accept-proxy mode 660$/gmu) ?? []).length, 1);
  assert.equal((haproxy.match(/^\s*stick-table /gmu) ?? []).length, 1);
  assert.equal((haproxy.match(/^\s*filter bwlim-out /gmu) ?? []).length, 2);
  assert.equal((haproxy.match(/^\s*http-request set-bandwidth-limit /gmu) ?? []).length, 2);
  assert.match(
    haproxy,
    /^\s*bind \/run\/bitcoinpir-directory-public-edge\/directory-public\.sock accept-proxy mode 660$/mu,
  );
  assert.match(haproxy, /^\s*server directory-public 127\.0\.0\.1:8080 maxconn 48$/mu);
  assert.match(haproxy, /^\s*no log$/mu);
  assert.match(haproxy, /stick-table type ipv6 size 4096 expire 2m nopurge/u);
  assert.match(haproxy, /src,ipmask\(32,64\)/u);
  assert.doesNotMatch(haproxy, /127\.0\.0\.1:(?!8080\b)[0-9]+/u);
  assert.doesNotMatch(
    haproxy,
    /provider|issuer|publisher|payment|send-proxy|stats socket|server-state|load-server-state|peers\b|spoe-agent|lua-load|server-template|resolvers\b|dlopen/iu,
  );
  for (const header of [
    "Authorization", "Baggage", "Cookie", "Forwarded", "Proxy-Authorization",
    "Traceparent", "Tracestate", "Via", "X-Correlation-ID", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Request-ID",
  ]) {
    assert.match(
      haproxy,
      new RegExp(`^\\s*http-request del-header ${header}$`, "imu"),
      header,
    );
  }
  assert.match(haproxy, /^\s*http-response del-header Set-Cookie$/mu);
});

test("directory-public unit and Caddy ordering drop-in stay separately sentinel-gated", () => {
  const unit = read("unit");
  const dropin = withoutComments(read("dropin"));
  const conditions = unit.match(/^ConditionPathExists=.*$/gmu) ?? [];
  assert.deepEqual(conditions, [
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-ACTIVATION-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-PREFLIGHT-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-SOURCE-READY-APPROVED",
    "ConditionPathExists=/etc/bitcoinpir/payment-v1/DIRECTORY-PUBLIC-EDGE-GENERATION-GUARD-IMPLEMENTED",
  ]);
  assert.match(unit, /^Before=bhtm-caddy\.service$/mu);
  assert.match(unit, /^User=bitcoinpir-directory-public-edge$/mu);
  assert.match(unit, /^Group=bitcoinpir-directory-public-edge$/mu);
  assert.match(unit, /^RuntimeDirectory=bitcoinpir-directory-public-edge$/mu);
  assert.match(unit, /^RuntimeDirectoryMode=0750$/mu);
  assert.match(unit, /^ProtectProc=invisible$/mu);
  assert.match(unit, /^ProcSubset=pid$/mu);
  assert.match(unit, /^IPAddressDeny=any$/mu);
  assert.match(unit, /^IPAddressAllow=localhost$/mu);
  assert.match(unit, /^LimitCORE=0$/mu);
  assert.match(unit, /^MemorySwapMax=0$/mu);
  assert.match(unit, /^Type=exec$/mu);
  assert.match(unit, /^Restart=no$/mu);
  assert.match(
    unit,
    /^ExecStart=\/opt\/bitcoinpir\/haproxy\/@HAPROXY_SHA256@\/haproxy -W -db -q -f \/etc\/bitcoinpir\/payment-v1\/directory-public-edge\/haproxy\.cfg$/mu,
  );
  assert.match(unit, /haproxy-build-manifest\.sha256/u);
  assert.match(unit, /^StandardOutput=null$/mu);
  assert.match(unit, /^StandardError=null$/mu);
  assert.doesNotMatch(unit, /^StateDirectory=|^RestartSec=|^NotifyAccess=|^\[Install\]$/mu);
  assert.doesNotMatch(unit, /(?:^|\s)-Ws(?:\s|$)/mu);

  assert.match(dropin, /^\[Unit\]$/mu);
  assert.match(
    dropin,
    /^Wants=bitcoinpir-payment-v1-directory-public-edge\.service$/mu,
  );
  assert.match(
    dropin,
    /^After=bitcoinpir-payment-v1-directory-public-edge\.service$/mu,
  );
  assert.doesNotMatch(dropin, /^\[Service\]|^Requires=|^BindsTo=/mu);
});

test("directory-public assets remain explicitly non-activating until integrated", () => {
  const readme = read("readme");
  assert.match(readme, /independent, non-activating\nasset set/u);
  assert.match(readme, /not activation-ready until the rendered profile/u);
  assert.match(readme, /UID 0 can create either path/u);
  assert.match(readme, /not a production security boundary/u);
  assert.match(readme, /source-ready receipt/u);
});

test("directory-public build manifest pins the exact static target-host recipe", () => {
  const manifestText = read("buildManifest");
  assert.equal((manifestText.match(/@HAPROXY_SHA256@/gu) ?? []).length, 3);
  const manifest = JSON.parse(
    manifestText.replaceAll("@HAPROXY_SHA256@", "0".repeat(64)),
  );
  assert.equal(manifest.source.version, "2.8.26");
  assert.equal(
    manifest.source.archive_sha256,
    "88c28dae25ea46672e66f8db0dadd1fb5920e06ee2415ceb9f281c256b537727",
  );
  assert.equal(manifest.compiler.version, "13.3.0");
  assert.deepEqual(manifest.build.independent_build_sha256, [
    "0".repeat(64),
    "0".repeat(64),
  ]);
  assert.equal(manifest.artifact.has_pt_interp, false);
  assert.equal(manifest.artifact.has_pt_dynamic, false);
  assert.deepEqual(manifest.disabled_options, [
    "USE_GETADDRINFO",
    "USE_LIBCRYPT",
    "USE_LUA",
    "USE_OPENSSL",
    "USE_SYSTEMD",
  ]);
  const gate = read("artifactGate");
  assert.match(gate, /forbidden PT_INTERP/u);
  assert.match(gate, /forbidden PT_DYNAMIC/u);
  assert.match(gate, /server-template/u);
});

test("directory-public renderer closes the static artifact and keeps both blockers", (t) => {
  const root = mkdtempSync(join(tmpdir(), "bpir-directory-public-render-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const sourceRoot = join(root, "source");
  const inputRoot = join(root, "input");
  const outputRoot = join(root, "bundle");
  mkdirSync(sourceRoot, { mode: 0o700 });
  mkdirSync(inputRoot, { mode: 0o700 });
  const templates = [
    "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
    "deploy/payment-v1/edge/directory-public-haproxy.cfg.in",
    "deploy/payment-v1/edge/integrated-existing-bhtm-caddy-directory-public.managed.Caddyfile.in",
    "deploy/payment-v1/systemd/bhtm-caddy.directory-public-edge.conf.in",
    "deploy/payment-v1/systemd/payment-v1-directory-public-edge.service.in",
    "scripts/payment-v1-directory-public-haproxy-artifact-gate.mjs",
  ];
  for (const sourcePath of templates) {
    const destination = join(sourceRoot, sourcePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(REPOSITORY, sourcePath), destination);
  }
  const binaryBytes = Buffer.from("reviewed-static-haproxy-test-artifact\n");
  const binarySha256 = sha256(binaryBytes);
  const placeholders = {
    DIRECTORY_RELAY_WSS_HOST: "directory.example.test",
    HAPROXY_SHA256: binarySha256,
    PUBLIC_HTTPS_BIND: "198.51.100.27",
  };
  const renderedConfig = Buffer.from(
    renderText("deploy/payment-v1/edge/directory-public-haproxy.cfg.in", placeholders),
  );
  const renderedBuildManifest = Buffer.from(
    renderText(
      "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
      placeholders,
    ),
  );
  const targets = {
    binary: `/opt/bitcoinpir/haproxy/${binarySha256}/haproxy`,
    binaryManifest: "/etc/bitcoinpir/payment-v1/directory-public-edge/haproxy.sha256",
    buildManifest:
      "/etc/bitcoinpir/payment-v1/directory-public-edge/haproxy-build-manifest.json",
    buildManifestManifest:
      "/etc/bitcoinpir/payment-v1/directory-public-edge/haproxy-build-manifest.sha256",
    config: "/etc/bitcoinpir/payment-v1/directory-public-edge/haproxy.cfg",
    configManifest:
      "/etc/bitcoinpir/payment-v1/directory-public-edge/directory-public-config.sha256",
  };
  const payloadInputs = [
    [targets.binary, binaryBytes, "binary", "0555"],
    [
      targets.binaryManifest,
      Buffer.from(`${binarySha256}  ${targets.binary}\n`),
      "hash-manifest",
      "0444",
    ],
    [
      targets.configManifest,
      Buffer.from(`${sha256(renderedConfig)}  ${targets.config}\n`),
      "hash-manifest",
      "0444",
    ],
    [
      targets.buildManifestManifest,
      Buffer.from(`${sha256(renderedBuildManifest)}  ${targets.buildManifest}\n`),
      "hash-manifest",
      "0444",
    ],
  ];
  const payloadArtifacts = payloadInputs.map(([targetPath, bytes, artifactClass, mode], index) => {
    const sourcePath = `payload/${String(index).padStart(2, "0")}`;
    const absolute = join(inputRoot, sourcePath);
    mkdirSync(dirname(absolute), { recursive: true });
    writeFileSync(absolute, bytes, { mode: 0o600 });
    return {
      class: artifactClass,
      expected_sha256: sha256(bytes),
      gid: 0,
      mode,
      source_path: sourcePath,
      target_path: targetPath,
      uid: 0,
    };
  });
  const metadata = new Map([
    [templates[0], { gid: 0, mode: "0444", target_path: targets.buildManifest, uid: 0 }],
    [templates[1], { gid: 52953, mode: "0440", target_path: targets.config, uid: 0 }],
    [templates[2], {
      gid: 0,
      mode: "0444",
      target_path:
        "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/directory-public.managed.Caddyfile",
      uid: 0,
    }],
    [templates[3], {
      gid: 0,
      mode: "0644",
      target_path:
        "/etc/systemd/system/bhtm-caddy.service.d/bitcoinpir-directory-public-edge.conf",
      uid: 0,
    }],
    [templates[4], {
      gid: 0,
      mode: "0644",
      target_path:
        "/etc/systemd/system/bitcoinpir-payment-v1-directory-public-edge.service",
      uid: 0,
    }],
    [templates[5], {
      gid: 0,
      mode: "0555",
      target_path:
        "/usr/local/libexec/bitcoinpir/payment-v1-directory-public-haproxy-artifact-gate.mjs",
      uid: 0,
    }],
  ]);
  const plan = {
    deployment_id: "directory-public-render-test",
    deployment_profile: "integrated-existing-bhtm-caddy-directory-public-v1",
    payload_artifacts: payloadArtifacts,
    placeholders,
    rendered_artifacts: templates.map((sourcePath) => ({
      ...metadata.get(sourcePath),
      source_path: sourcePath,
      source_sha256: sha256(readFileSync(join(sourceRoot, sourcePath))),
    })),
    schema_version: 2,
    service_identities: [{
      gid: 52953,
      group_name: "bitcoinpir-directory-public-edge",
      uid: 52953,
      unit_name: "bitcoinpir-payment-v1-directory-public-edge.service",
      user_name: "bitcoinpir-directory-public-edge",
    }],
    systemd_version: REVIEWED_SYSTEMD_VERSION,
  };
  const approvedPlanSha256 = computeApprovedPlanSha256(plan);
  const model = renderBundle({
    approvedPlanSha256,
    inputRoot,
    outputRoot,
    plan,
    sourceRoot,
  });
  verifyBundle({
    approvedPlanSha256,
    bundleRoot: outputRoot,
    inputRoot,
    plan,
    sourceRoot,
  });
  assert.equal(model.manifest.deployment_profile, plan.deployment_profile);
  assert.deepEqual(model.request.runtime_paths, [
    {
      file_type: "directory",
      gid: 52953,
      mode: "0750",
      target_path: "/run/bitcoinpir-directory-public-edge",
      uid: 52953,
    },
    {
      file_type: "socket",
      gid: 52953,
      mode: "0660",
      target_path:
        "/run/bitcoinpir-directory-public-edge/directory-public.sock",
      uid: 52953,
    },
  ]);
  const [unit] = model.manifest.runtime_units;
  assert.equal(unit.hardening.Type[0], "exec");
  assert.equal(unit.hardening.Restart[0], "no");
  assert.match(unit.exec_start[0], /\/haproxy -W -db -q -f /u);
  assert.match(unit.conditions.join("\n"), /SOURCE-READY-APPROVED/u);
  assert.match(unit.conditions.join("\n"), /GENERATION-GUARD-IMPLEMENTED/u);
});

test("installed HAProxy accepts the single-lane template", {
  skip: commandFromEnvironment("BPIR_HAPROXY_BIN", [
    "/usr/sbin/haproxy",
    "/usr/local/sbin/haproxy",
    "/opt/homebrew/bin/haproxy",
  ]) === undefined,
}, () => {
  const haproxy = commandFromEnvironment("BPIR_HAPROXY_BIN", [
    "/usr/sbin/haproxy",
    "/usr/local/sbin/haproxy",
    "/opt/homebrew/bin/haproxy",
  ]);
  const result = spawnSync(haproxy, ["-c", "-q", "-f", join(REPOSITORY, paths.haproxy)], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(
    result.status,
    0,
    `${result.error?.message ?? ""}\n${result.stdout ?? ""}\n${result.stderr ?? ""}`,
  );
});

test("installed Caddy adapts the single-site managed block", {
  skip: commandFromEnvironment("BPIR_CADDY_BIN", [
    "/usr/bin/caddy",
    "/usr/local/bin/caddy",
    "/opt/homebrew/bin/caddy",
  ]) === undefined,
}, () => {
  const caddy = commandFromEnvironment("BPIR_CADDY_BIN", [
    "/usr/bin/caddy",
    "/usr/local/bin/caddy",
    "/opt/homebrew/bin/caddy",
  ]);
  const rendered = read("caddy")
    .replaceAll("@DIRECTORY_RELAY_WSS_HOST@", "relay.example.test")
    .replaceAll("@PUBLIC_HTTPS_BIND@", "127.0.0.1");
  const result = spawnSync(
    caddy,
    ["adapt", "--config", "-", "--adapter", "caddyfile", "--pretty"],
    {
    encoding: "utf8",
    input: rendered,
    shell: false,
    },
  );
  assert.equal(
    result.status,
    0,
    `${result.error?.message ?? ""}\n${result.stdout ?? ""}\n${result.stderr ?? ""}`,
  );
  const adapted = JSON.parse(result.stdout);
  const encoded = JSON.stringify(adapted);
  assert.match(encoded, /relay\.example\.test/u);
  assert.match(encoded, /\/run\/bitcoinpir-directory-public-edge\/directory-public\.sock/u);
  assert.doesNotMatch(encoded, /provider|issuer|publisher|payment/iu);
});
