import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const REPOSITORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const paths = Object.freeze({
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
    /provider|issuer|publisher|payment|send-proxy|stats socket|server-state|load-server-state|peers\b|spoe-agent|lua-load/iu,
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
  assert.match(unit, /^StandardOutput=null$/mu);
  assert.match(unit, /^StandardError=null$/mu);
  assert.doesNotMatch(unit, /^StateDirectory=|^\[Install\]$/mu);

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
