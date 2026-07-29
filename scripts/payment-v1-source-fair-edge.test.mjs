import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import tls from "node:tls";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(SCRIPT_DIRECTORY, "..");
const HAPROXY_TEMPLATE = join(
  REPOSITORY,
  "deploy/payment-v1/edge/source-fair-haproxy.cfg.in",
);
const CADDY_TEMPLATE = join(
  REPOSITORY,
  "deploy/payment-v1/edge/hetzner-public.Caddyfile.in",
);
const INTEGRATED_CADDY_BLOCK = join(
  REPOSITORY,
  "deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in",
);
const ROLLBACK_CADDY_TEMPLATE = join(
  REPOSITORY,
  "deploy/payment-v1/edge/rollback-authority.Caddyfile.in",
);

function read(relativePath) {
  return readFileSync(join(REPOSITORY, relativePath), "utf8");
}

function commandFromEnvironment(name, candidates) {
  const explicit = process.env[name];
  if (explicit !== undefined) {
    assert.equal(explicit.startsWith("/"), true, `${name} must be an absolute path`);
    assert.equal(existsSync(explicit), true, `${name} does not exist`);
    return explicit;
  }
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  const commandName = {
    BPIR_CADDY_BIN: "caddy",
    BPIR_HAPROXY_BIN: "haproxy",
    BPIR_OPENSSL_BIN: "openssl",
  }[name];
  assert.ok(commandName, `unknown binary environment key ${name}`);
  const found = spawnSync("/usr/bin/env", ["which", commandName], {
    encoding: "utf8",
    shell: false,
  });
  return found.status === 0 ? found.stdout.trim() : undefined;
}

const HAPROXY = commandFromEnvironment("BPIR_HAPROXY_BIN", [
  "/usr/sbin/haproxy",
  "/usr/local/sbin/haproxy",
  "/opt/homebrew/bin/haproxy",
]);
const CADDY = commandFromEnvironment("BPIR_CADDY_BIN", [
  "/usr/bin/caddy",
  "/usr/local/bin/caddy",
  "/opt/homebrew/bin/caddy",
]);
const OPENSSL = commandFromEnvironment("BPIR_OPENSSL_BIN", [
  "/usr/bin/openssl",
  "/usr/local/bin/openssl",
  "/opt/homebrew/bin/openssl",
]);

function withoutComments(text) {
  return text
    .split("\n")
    .map((line) => line.replace(/\s+#.*$/u, ""))
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
}

test("source-fair templates close persistence, bypass, and source-header channels", () => {
  const haproxy = withoutComments(readFileSync(HAPROXY_TEMPLATE, "utf8"));
  const caddy = withoutComments(readFileSync(CADDY_TEMPLATE, "utf8"));
  const rollbackCaddy = withoutComments(
    readFileSync(ROLLBACK_CADDY_TEMPLATE, "utf8"),
  );
  const publicUnit = read("deploy/payment-v1/systemd/payment-v1-public-edge.service.in");
  const sourceFairUnit = read(
    "deploy/payment-v1/systemd/payment-v1-source-fair-edge.service.in",
  );
  const rollbackUnit = read("deploy/payment-v1/systemd/payment-v1-edge.service.in");

  assert.equal((haproxy.match(/^\s*stick-table .* expire 2m nopurge /gmu) ?? []).length, 6);
  assert.equal((haproxy.match(/^\s*bind .* accept-proxy mode 660$/gmu) ?? []).length, 4);
  assert.equal((haproxy.match(/^\s*filter bwlim-out /gmu) ?? []).length, 8);
  assert.equal((haproxy.match(/^\s*http-request set-bandwidth-limit /gmu) ?? []).length, 8);
  assert.match(haproxy, /stick-table type integer size 1 expire 2m nopurge/u);
  assert.match(haproxy, /type ipv6 size 64 expire 2m nopurge/u);
  assert.equal((haproxy.match(/type ipv6 size 4096 expire 2m nopurge/gu) ?? []).length, 4);
  assert.equal((haproxy.match(/src,ipmask\(32,64\)/gu) ?? []).length >= 14, true);
  assert.equal(
    (haproxy.match(/^\s*http-request deny deny_status 429 unless \{ sc0_tracked \}$/gmu) ?? [])
      .length,
    4,
  );
  assert.equal(
    (haproxy.match(/^\s*http-request deny deny_status 429 if quote_create !\{ sc[12]_tracked \}$/gmu) ?? [])
      .length,
    2,
  );
  assert.match(haproxy, /sc1_http_req_rate gt 6/u);
  assert.match(haproxy, /sc2_http_req_rate gt 60/u);
  assert.match(haproxy, /^\s*maxconn 320$/mu);
  assert.match(haproxy, /^\s*no log$/mu);
  assert.doesNotMatch(
    haproxy,
    /^\s*(?:log(?!-format\b)|stats socket|server-state|load-server-state|peers\b|spoe-agent|lua-load)\b/mu,
  );
  assert.doesNotMatch(haproxy, /\bsend-proxy(?:-v2)?\b/u);
  assert.doesNotMatch(haproxy, /^\s*http-request (?:add|set)-header\b/mu);
  assert.doesNotMatch(haproxy, /127\.0\.0\.1:8099/u);
  for (const backend of [
    "127.0.0.1:8191",
    "127.0.0.1:5610",
    "127.0.0.1:8080",
    "127.0.0.1:8081",
  ]) {
    assert.match(haproxy, new RegExp(`server [^\\n]+ ${backend.replaceAll(".", "\\.")}`));
  }
  for (const header of [
    "Baggage", "CF-Connecting-IP", "Client-IP", "Fastly-Client-IP",
    "Fly-Client-IP", "Forwarded", "Traceparent", "Tracestate",
    "True-Client-IP", "Via", "X-Client-IP", "X-Cluster-Client-IP",
    "X-Correlation-ID", "X-Envoy-External-Address", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Original-Client-IP",
    "X-Original-Forwarded-For", "X-Real-IP", "X-Request-ID",
  ]) {
    assert.equal(
      (haproxy.match(new RegExp(`^\\s*http-request del-header ${header}$`, "gimu")) ?? []).length,
      4,
      header,
    );
  }

  assert.equal((caddy.match(/proxy_protocol v2/gu) ?? []).length, 7);
  assert.equal((caddy.match(/header_up -\*/gu) ?? []).length, 7);
  assert.doesNotMatch(
    caddy,
    /header_up\s+(?:CF-Connecting-IP|Client-IP|Fastly-Client-IP|Fly-Client-IP|Forwarded|True-Client-IP|X-Client-IP|X-Cluster-Client-IP|X-Envoy-External-Address|X-Forwarded(?:-[A-Za-z0-9-]+)?|X-Original-(?:Client-IP|Forwarded-For)|X-Real-IP)\b/iu,
  );
  assert.match(caddy, /bind @DIRECTORY_PUBLISHER_PRIVATE_BIND@/u);
  assert.match(caddy, /remote_ip @DIRECTORY_PUBLISHER_CLIENT_IP@/u);
  assert.doesNotMatch(caddy, /client_auth|trust_pool|directory-publisher-client-ca\.pem/u);
  assert.match(
    haproxy,
    /http-request deny deny_status 403 unless \{ src @DIRECTORY_PUBLISHER_CLIENT_IP@ \}/u,
  );

  assert.match(publicUnit, /^Requires=bitcoinpir-payment-v1-source-fair-edge\.service$/mu);
  assert.match(publicUnit, /^BindsTo=bitcoinpir-payment-v1-source-fair-edge\.service$/mu);
  assert.match(
    publicUnit,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED$/mu,
  );
  assert.match(
    publicUnit,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/EDGE-ACTIVATION-APPROVED$/mu,
  );
  assert.match(publicUnit, /^LimitCORE=0$/mu);
  assert.match(publicUnit, /^MemoryMax=536870912$/mu);
  assert.match(publicUnit, /^MemorySwapMax=0$/mu);
  assert.match(publicUnit, /^TasksMax=512$/mu);
  assert.match(publicUnit, /^StandardOutput=null$/mu);
  assert.match(publicUnit, /^StandardError=null$/mu);
  assert.match(sourceFairUnit, /^RuntimeDirectory=bitcoinpir-source-fair-edge$/mu);
  assert.match(
    sourceFairUnit,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED$/mu,
  );
  assert.match(
    sourceFairUnit,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/EDGE-ACTIVATION-APPROVED$/mu,
  );
  assert.doesNotMatch(sourceFairUnit, /^StateDirectory=/mu);
  assert.match(sourceFairUnit, /^LimitCORE=0$/mu);
  assert.match(sourceFairUnit, /^MemoryMax=268435456$/mu);
  assert.match(sourceFairUnit, /^MemorySwapMax=0$/mu);
  assert.match(sourceFairUnit, /^TasksMax=128$/mu);
  assert.match(sourceFairUnit, /^StandardOutput=null$/mu);
  assert.match(sourceFairUnit, /^StandardError=null$/mu);

  assert.match(rollbackCaddy, /bind @ROLLBACK_AUTHORITY_PRIVATE_BIND@/u);
  assert.match(
    rollbackCaddy,
    /tls \/etc\/bitcoinpir\/payment-v1\/edge\/rollback-authority-server\.crt \/etc\/bitcoinpir\/payment-v1\/edge\/rollback-authority-server\.key/u,
  );
  assert.doesNotMatch(rollbackCaddy, /client_auth|trust_pool/u);
  assert.match(
    rollbackUnit,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/ROLLBACK-AUTHORITY-PRIVATE-INGRESS-APPROVED$/mu,
  );
  assert.match(
    rollbackUnit,
    /^ConditionPathExists=\/etc\/bitcoinpir\/payment-v1\/ROLLBACK-EDGE-ACTIVATION-APPROVED$/mu,
  );
  assert.match(rollbackUnit, /^RuntimeDirectory=bitcoinpir-rollback-authority-edge$/mu);
  assert.doesNotMatch(rollbackUnit, /^StateDirectory=/mu);
  assert.match(rollbackUnit, /^IPAddressDeny=any$/mu);
  assert.match(rollbackUnit, /^IPAddressAllow=localhost @ROLLBACK_AUTHORITY_CLIENT_IP@$/mu);
  assert.match(rollbackUnit, /^LimitCORE=0$/mu);
  assert.match(rollbackUnit, /^MemorySwapMax=0$/mu);
  assert.match(rollbackUnit, /^StandardOutput=null$/mu);
  assert.match(rollbackUnit, /^StandardError=null$/mu);

  for (const unitPath of [
    "deploy/payment-v1/systemd/hetzner-provider.service.in",
    "deploy/payment-v1/systemd/hetzner-payment-issuer.service.in",
    "deploy/payment-v1/systemd/hetzner-directory-relay.service.in",
  ]) {
    assert.match(read(unitPath), /^InaccessiblePaths=.*\/run\/bitcoinpir-source-fair-edge/mu);
  }
});

test("the selected HAProxy binary supports systemd readiness", {
  skip: HAPROXY === undefined,
}, () => {
  const version = spawnSync(HAPROXY, ["-vv"], {
    encoding: "utf8",
    shell: false,
  });
  const output = `${version.stdout}\n${version.stderr}`;
  assert.equal(version.status, 0, output);
  assert.match(output, /^HAProxy version 2\.8\./mu);
  assert.match(output, /(?:^|\s)\+SYSTEMD(?:\s|$)/mu);
});

test("the selected Caddy binary validates complete IPv4 and IPv6-ULA public templates", {
  skip: CADDY === undefined || OPENSSL === undefined,
}, (t) => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-caddy-template-"));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const certificate = join(directory, "publisher.crt");
  const key = join(directory, "publisher.key");
  const generated = spawnSync(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key,
    "-out", certificate,
    "-days", "1",
    "-subj", "/CN=publisher.example.net",
  ], { encoding: "utf8", shell: false });
  assert.equal(generated.status, 0, generated.stderr);
  const profiles = [
    {
      label: "ipv4",
      publisherClientIp: "10.77.0.1",
      publisherPrivateBind: "10.77.0.2",
      publicBind: "127.0.0.1",
    },
    {
      label: "ipv6-ula",
      publisherClientIp: "fd42:6270:6972:1::1",
      publisherPrivateBind: "fd42:6270:6972:1::2",
      publicBind: "2001:db8::10",
    },
  ];
  for (const profile of profiles) {
    let rendered = readFileSync(CADDY_TEMPLATE, "utf8");
    for (const [placeholder, value] of Object.entries({
      DIRECTORY_PUBLISHER_CLIENT_IP: profile.publisherClientIp,
      DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
      DIRECTORY_PUBLISHER_PRIVATE_BIND: profile.publisherPrivateBind,
      DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
      PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
      PROVIDER_WSS_HOST: "pir.example.net",
      PUBLIC_HTTPS_BIND: profile.publicBind,
    })) {
      rendered = rendered.replaceAll(`@${placeholder}@`, value);
    }
    rendered = rendered
      .replaceAll(
        "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
        certificate,
      )
      .replaceAll(
        "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
        key,
      );
    assert.doesNotMatch(rendered, /@[A-Z][A-Z0-9_]+@/u);
    const config = join(directory, `${profile.label}.Caddyfile`);
    writeFileSync(config, rendered, { mode: 0o600 });
    const validation = spawnSync(CADDY, [
      "validate", "--config", config, "--adapter", "caddyfile",
    ], { encoding: "utf8", shell: false });
    assert.equal(
      validation.status,
      0,
      `${profile.label} complete Caddy template validation failed:\n${validation.stdout}\n${validation.stderr}`,
    );
  }
});

test("the selected Caddy binary validates an exact existing-config plus integrated managed block", {
  skip: CADDY === undefined || OPENSSL === undefined,
}, (t) => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-integrated-caddy-template-"));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const certificate = join(directory, "publisher.crt");
  const key = join(directory, "publisher.key");
  const generated = spawnSync(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key,
    "-out", certificate,
    "-days", "1",
    "-subj", "/CN=publisher.example.net",
  ], { encoding: "utf8", shell: false });
  assert.equal(generated.status, 0, generated.stderr);
  let block = readFileSync(INTEGRATED_CADDY_BLOCK, "utf8");
  for (const [placeholder, value] of Object.entries({
    DIRECTORY_PUBLISHER_CLIENT_IP: "10.77.0.1",
    DIRECTORY_PUBLISHER_HTTPS_HOST: "publisher.example.net",
    DIRECTORY_PUBLISHER_PRIVATE_BIND: "10.77.0.2",
    DIRECTORY_RELAY_WSS_HOST: "directory.example.net",
    PAYMENT_ISSUER_HTTPS_HOST: "pay.example.net",
    PROVIDER_WSS_HOST: "pir.example.net",
    PUBLIC_HTTPS_BIND: "198.51.100.23",
  })) {
    block = block.replaceAll(`@${placeholder}@`, value);
  }
  block = block
    .replaceAll(
      "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
      certificate,
    )
    .replaceAll(
      "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
      key,
    );
  assert.doesNotMatch(block, /@[A-Z][A-Z0-9_]+@/u);
  const config = join(directory, "integrated.Caddyfile");
  writeFileSync(
    config,
    `existing.example.net {\n\trespond "existing" 200\n}\n\n${block}`,
    { mode: 0o600 },
  );
  const adapted = spawnSync(CADDY, [
    "adapt", "--config", config, "--adapter", "caddyfile",
  ], { encoding: "utf8", shell: false });
  assert.equal(
    adapted.status,
    0,
    `integrated Caddy adapt failed:\n${adapted.stdout}\n${adapted.stderr}`,
  );
  assert.doesNotThrow(() => JSON.parse(adapted.stdout));
  const validation = spawnSync(CADDY, [
    "validate", "--config", config, "--adapter", "caddyfile",
  ], { encoding: "utf8", shell: false });
  assert.equal(
    validation.status,
    0,
    `integrated Caddy validate failed:\n${validation.stdout}\n${validation.stderr}`,
  );
});

test("the selected Caddy binary validates the private rollback template", {
  skip: CADDY === undefined || OPENSSL === undefined,
}, (t) => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-rollback-caddy-template-"));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const certificate = join(directory, "rollback.crt");
  const key = join(directory, "rollback.key");
  const generated = spawnSync(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key,
    "-out", certificate,
    "-days", "1",
    "-subj", "/CN=authority.example.net",
  ], { encoding: "utf8", shell: false });
  assert.equal(generated.status, 0, generated.stderr);
  const rendered = readFileSync(ROLLBACK_CADDY_TEMPLATE, "utf8")
    .replaceAll("@ROLLBACK_AUTHORITY_HTTPS_HOST@", "authority.example.net")
    .replaceAll("@ROLLBACK_AUTHORITY_PRIVATE_BIND@", "127.0.0.3")
    .replaceAll(
      "/etc/bitcoinpir/payment-v1/edge/rollback-authority-server.crt",
      certificate,
    )
    .replaceAll(
      "/etc/bitcoinpir/payment-v1/edge/rollback-authority-server.key",
      key,
    );
  assert.doesNotMatch(rendered, /@[A-Z][A-Z0-9_]+@/u);
  const config = join(directory, "Caddyfile");
  writeFileSync(config, rendered, { mode: 0o600 });
  const validation = spawnSync(CADDY, [
    "validate", "--config", config, "--adapter", "caddyfile",
  ], { encoding: "utf8", shell: false });
  assert.equal(
    validation.status,
    0,
    `rollback Caddy template validation failed:\n${validation.stdout}\n${validation.stderr}`,
  );
});

function ipv6Bytes(address) {
  assert.equal(net.isIP(address), 6, `${address} is not IPv6`);
  const halves = address.split("::");
  assert.equal(halves.length <= 2, true, `${address} has multiple :: compressions`);
  const left = halves[0] === "" ? [] : halves[0].split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1].split(":");
  const omitted = 8 - left.length - right.length;
  if (halves.length === 1) assert.equal(omitted, 0, `${address} is not full-width IPv6`);
  else assert.equal(omitted >= 1, true, `${address} has no compressed IPv6 word`);
  const words = [...left, ...Array(omitted).fill("0"), ...right];
  assert.equal(words.length, 8);
  const bytes = Buffer.alloc(16);
  for (const [index, word] of words.entries()) {
    assert.match(word, /^[0-9a-f]{1,4}$/iu, `${address} has an invalid IPv6 word`);
    bytes.writeUInt16BE(Number.parseInt(word, 16), index * 2);
  }
  return bytes;
}

function ipBytes(address, family) {
  assert.equal(net.isIP(address), family, `${address} does not use IP family ${family}`);
  if (family === 6) return ipv6Bytes(address);
  const octets = address.split(".").map(Number);
  assert.equal(octets.length, 4);
  assert.equal(octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255), true);
  return Buffer.from(octets);
}

function proxyV2Header(sourceIp, destinationIp) {
  const family = net.isIP(sourceIp);
  assert.equal(family === 4 || family === 6, true, `${sourceIp} is not an IP address`);
  const effectiveDestination = destinationIp ?? (family === 4 ? "127.0.0.1" : "fd42:6270:6972:ffff::1");
  const source = ipBytes(sourceIp, family);
  const destination = ipBytes(effectiveDestination, family);
  const addressLength = family === 4 ? 12 : 36;
  const header = Buffer.alloc(16 + addressLength);
  Buffer.from("\r\n\r\n\0\r\nQUIT\n", "binary").copy(header, 0);
  header[12] = 0x21;
  header[13] = family === 4 ? 0x11 : 0x21;
  header.writeUInt16BE(addressLength, 14);
  Buffer.from(source).copy(header, 16);
  Buffer.from(destination).copy(header, 16 + source.length);
  const portsOffset = 16 + source.length + destination.length;
  header.writeUInt16BE(40_000, portsOffset);
  header.writeUInt16BE(443, portsOffset + 2);
  return header;
}

function waitFor(predicate, label, timeoutMs = 5_000) {
  const started = Date.now();
  return new Promise((resolvePromise, rejectPromise) => {
    const poll = () => {
      if (predicate()) {
        resolvePromise();
        return;
      }
      if (Date.now() - started > timeoutMs) {
        rejectPromise(new Error(`timed out waiting for ${label}`));
        return;
      }
      setTimeout(poll, 10);
    };
    poll();
  });
}

function listen(server, host = "127.0.0.1", port = 0) {
  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(port, host, () => {
      server.off("error", rejectPromise);
      resolvePromise(server.address());
    });
  });
}

function closeServer(server) {
  return new Promise((resolvePromise) => server.close(() => resolvePromise()));
}

function listenUnix(server, socketPath) {
  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(socketPath, () => {
      server.off("error", rejectPromise);
      resolvePromise();
    });
  });
}

function stopProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolvePromise) => {
    const timer = setTimeout(() => child.kill("SIGKILL"), 2_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolvePromise();
    });
    child.kill("SIGTERM");
  });
}

function backendServer({ hold = false } = {}) {
  const records = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket));
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (!bytes.includes(Buffer.from("\r\n\r\n"))) return;
      if (records.some((record) => record.socket === socket)) return;
      const raw = bytes.toString("latin1");
      records.push({ remoteAddress: socket.remoteAddress, raw, socket });
      if (!hold) {
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
      }
    });
  });
  return {
    records,
    server,
    destroySockets() {
      for (const socket of sockets) socket.destroy();
    },
  };
}

function proxyV2BackendServer() {
  const records = [];
  const sockets = new Set();
  const signature = Buffer.from("\r\n\r\n\0\r\nQUIT\n", "binary");
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket));
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length < 16 || records.some((record) => record.socket === socket)) return;
      try {
        assert.deepEqual(bytes.subarray(0, 12), signature);
        assert.equal(bytes[12], 0x21);
        assert.equal(bytes[13], 0x11);
        const headerLength = bytes.readUInt16BE(14);
        const payloadOffset = 16 + headerLength;
        if (bytes.length < payloadOffset) return;
        const payload = bytes.subarray(payloadOffset);
        if (!payload.includes(Buffer.from("\r\n\r\n"))) return;
        const sourceAddress = [...bytes.subarray(16, 20)].join(".");
        records.push({ raw: payload.toString("latin1"), socket, sourceAddress });
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
      } catch (error) {
        records.push({ error, raw: "", socket, sourceAddress: "" });
        socket.destroy();
      }
    });
  });
  return {
    records,
    server,
    destroySockets() {
      for (const socket of sockets) socket.destroy();
    },
  };
}

async function openProxyRequest(socketPath, sourceIp, request) {
  const socket = net.createConnection({ path: socketPath });
  let response = Buffer.alloc(0);
  let connected = false;
  const responsePromise = new Promise((resolvePromise, rejectPromise) => {
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
    });
    socket.on("end", () => {
      resolvePromise(response.toString("latin1"));
    });
    socket.on("error", (error) => {
      if (connected) resolvePromise(response.toString("latin1"));
      else rejectPromise(error);
    });
  });
  await new Promise((resolvePromise, rejectPromise) => {
    const onError = (error) => rejectPromise(error);
    socket.once("error", onError);
    socket.once("connect", () => {
      socket.off("error", onError);
      connected = true;
      resolvePromise();
    });
  });
  socket.write(Buffer.concat([proxyV2Header(sourceIp), Buffer.from(request, "latin1")]));
  return { responsePromise, socket };
}

async function requestAndRead(socketPath, sourceIp, request) {
  const opened = await openProxyRequest(socketPath, sourceIp, request);
  return opened.responsePromise;
}

function statusOf(response) {
  const match = /^HTTP\/1\.[01] ([0-9]{3})\b/u.exec(response);
  assert.ok(match, `missing HTTP response status: ${JSON.stringify(response.slice(0, 120))}`);
  return Number(match[1]);
}

function laneRecordCounts(harness) {
  return Object.fromEntries(
    Object.entries(harness.lanes).map(([name, lane]) => [name, lane.records.length]),
  );
}

function recursivelyCollect(value, predicate, collected = []) {
  if (Array.isArray(value)) {
    for (const item of value) recursivelyCollect(item, predicate, collected);
    return collected;
  }
  if (value === null || typeof value !== "object") return collected;
  if (predicate(value)) collected.push(value);
  for (const nested of Object.values(value)) {
    recursivelyCollect(nested, predicate, collected);
  }
  return collected;
}

function assertRenderedCaddyJsonClosure(caddyfile, harness, edgePort) {
  const adapted = spawnSync(CADDY, [
    "adapt", "--config", caddyfile, "--adapter", "caddyfile",
  ], { encoding: "utf8", shell: false });
  assert.equal(
    adapted.status,
    0,
    `complete rendered Caddy lane config failed adaptation:\n${adapted.stdout}\n${adapted.stderr}`,
  );
  const configuration = JSON.parse(adapted.stdout);
  assert.equal(
    recursivelyCollect(
      configuration,
      (value) => Object.hasOwn(value, "named_routes"),
    ).length,
    0,
    "adapted Caddy JSON must not contain named routes",
  );

  const servers = Object.values(configuration.apps?.http?.servers ?? {});
  assert.equal(servers.length, 2, "adapted Caddy JSON must contain exactly two listeners");
  const byListen = new Map(servers.map((server) => {
    assert.equal(Array.isArray(server.listen), true);
    assert.equal(server.listen.length, 1);
    return [server.listen[0], server];
  }));
  assert.deepEqual(
    [...byListen.keys()].sort(),
    [`127.0.0.1:${edgePort}`, `127.0.0.2:${edgePort}`],
  );

  const expected = new Map([
    [`127.0.0.1:${edgePort}`, {
      hosts: ["directory.example.net", "pay.example.net", "pir.example.net"],
      sockets: [
        harness.sockets.directoryPublic,
        ...Array(4).fill(harness.sockets.issuer),
        harness.sockets.provider,
      ],
      static404s: 4,
    }],
    [`127.0.0.2:${edgePort}`, {
      hosts: ["publisher.example.net"],
      sockets: [harness.sockets.directoryPublisher],
      static404s: 2,
    }],
  ]);
  for (const [listener, expectedServer] of expected) {
    const server = byListen.get(listener);
    const hosts = recursivelyCollect(
      server,
      (value) => Array.isArray(value.host),
    ).flatMap((value) => value.host);
    assert.deepEqual([...new Set(hosts)].sort(), expectedServer.hosts);
    assert.equal(
      recursivelyCollect(
        server,
        (value) => value.handler === "static_response" && value.status_code === 404,
      ).length,
      expectedServer.static404s,
    );
    const handlers = recursivelyCollect(
      server,
      (value) => value.handler === "reverse_proxy",
    );
    const actualSockets = [];
    for (const handler of handlers) {
      assert.equal(handler.transport?.proxy_protocol, "v2");
      assert.deepEqual(handler.headers?.request?.delete, ["*"]);
      assert.equal(handler.upstreams?.length, 1);
      const dial = handler.upstreams[0].dial;
      assert.equal(dial.startsWith("unix/"), true, `unexpected Caddy dial ${dial}`);
      actualSockets.push(dial.slice("unix/".length));
    }
    assert.deepEqual(actualSockets.sort(), [...expectedServer.sockets].sort());
  }
}

async function createHarness(
  t,
  {
    providerHold = false,
    providerSourceTableSize = 4096,
    publisherClientIp = "198.20.0.1",
  } = {},
) {
  assert.ok(HAPROXY, "HAProxy integration requested without an installed binary");
  assert.equal(Number.isSafeInteger(providerSourceTableSize), true);
  assert.equal(providerSourceTableSize > 0, true);
  assert.equal(net.isIP(publisherClientIp) !== 0, true, "publisher client must be an IP address");
  const directory = mkdtempSync(join(tmpdir(), "bpir-source-fair-"));
  chmodSync(directory, 0o700);
  const lanes = {
    directoryPublic: backendServer(),
    directoryPublisher: backendServer(),
    issuer: backendServer(),
    provider: backendServer({ hold: providerHold }),
  };
  const addresses = {};
  for (const [name, lane] of Object.entries(lanes)) {
    addresses[name] = await listen(lane.server);
  }
  let config = readFileSync(HAPROXY_TEMPLATE, "utf8");
  const providerTable =
    "stick-table type ipv6 size 4096 expire 2m nopurge store conn_cur,conn_rate(10s),bytes_out_rate(1s)";
  assert.equal(config.includes(providerTable), true);
  config = config.replace(
    providerTable,
    providerTable.replace("size 4096", `size ${providerSourceTableSize}`),
  );
  config = config.replaceAll("/run/bitcoinpir-source-fair-edge", directory);
  config = config.replaceAll("@DIRECTORY_PUBLISHER_CLIENT_IP@", publisherClientIp);
  for (const [original, replacement] of [
    ["127.0.0.1:8191", `127.0.0.1:${addresses.provider.port}`],
    ["127.0.0.1:5610", `127.0.0.1:${addresses.issuer.port}`],
    ["127.0.0.1:8080", `127.0.0.1:${addresses.directoryPublic.port}`],
    ["127.0.0.1:8081", `127.0.0.1:${addresses.directoryPublisher.port}`],
  ]) {
    config = config.replaceAll(original, replacement);
  }
  const configPath = join(directory, "haproxy.cfg");
  writeFileSync(configPath, config, { mode: 0o600 });
  const validation = spawnSync(HAPROXY, ["-c", "-f", configPath], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(
    validation.status,
    0,
    `HAProxy validation failed:\n${validation.stdout}\n${validation.stderr}`,
  );
  const child = spawn(HAPROXY, ["-db", "-f", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const sockets = {
    directoryPublic: join(directory, "directory-public.sock"),
    directoryPublisher: join(directory, "directory-publisher.sock"),
    issuer: join(directory, "issuer.sock"),
    provider: join(directory, "provider.sock"),
  };
  await waitFor(
    () => Object.values(sockets).every(existsSync) || child.exitCode !== null,
    "HAProxy Unix sockets",
  );
  assert.equal(child.exitCode, null, `HAProxy exited during startup: ${output}`);
  t.after(async () => {
    for (const lane of Object.values(lanes)) lane.destroySockets();
    await stopProcess(child);
    await Promise.all(Object.values(lanes).map((lane) => closeServer(lane.server)));
    rmSync(directory, { recursive: true, force: true });
  });
  return { child, directory, lanes, sockets };
}

const providerRequest =
  "GET /v1/pir HTTP/1.1\r\nHost: pir.example.net\r\nConnection: close\r\n\r\n";
const quoteRequest =
  "POST /v1/quotes/bolt11 HTTP/1.1\r\nHost: pay.example.net\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const directoryPublisherRequest =
  "GET /v1/directory HTTP/1.1\r\nHost: publisher.example.net\r\nConnection: close\r\n\r\n";

test("HAProxy enforces per-source upgraded-connection slots without cross-source starvation", {
  skip: HAPROXY === undefined,
}, async (t) => {
  const harness = await createHarness(t, { providerHold: true });
  const held = [];
  for (let index = 0; index < 8; index += 1) {
    held.push(await openProxyRequest(harness.sockets.provider, "198.18.0.1", providerRequest));
  }
  await waitFor(() => harness.lanes.provider.records.length === 8, "eight admitted provider streams");
  const rejected = await requestAndRead(harness.sockets.provider, "198.18.0.1", providerRequest);
  assert.equal(statusOf(rejected), 429);

  const other = await openProxyRequest(harness.sockets.provider, "198.18.0.2", providerRequest);
  held.push(other);
  await waitFor(() => harness.lanes.provider.records.length === 9, "independent-source provider stream");
  for (const connection of held) connection.socket.destroy();
});

test("HAProxy fails closed when concurrent new sources race for the final table entry", {
  skip: HAPROXY === undefined,
}, async (t) => {
  const harness = await createHarness(t, { providerSourceTableSize: 1 });
  const sources = Array.from(
    { length: 32 },
    (_, index) => `198.20.0.${index + 1}`,
  );
  const responses = await Promise.all(
    sources.map((source) =>
      requestAndRead(harness.sockets.provider, source, providerRequest)
    ),
  );
  const statuses = responses.map(statusOf);
  assert.equal(statuses.filter((status) => status === 200).length, 1);
  assert.equal(statuses.filter((status) => status === 429).length, sources.length - 1);
  assert.equal(harness.lanes.provider.records.length, 1);

  const admittedSource = sources[statuses.indexOf(200)];
  assert.equal(
    statusOf(await requestAndRead(harness.sockets.provider, admittedSource, providerRequest)),
    200,
  );
  assert.equal(harness.lanes.provider.records.length, 2);
});

test("HAProxy isolates per-source and global quote budgets", {
  skip: HAPROXY === undefined,
}, async (t) => {
  const sourceHarness = await createHarness(t);
  for (let index = 0; index < 6; index += 1) {
    assert.equal(
      statusOf(await requestAndRead(sourceHarness.sockets.issuer, "198.18.1.1", quoteRequest)),
      200,
    );
  }
  assert.equal(
    statusOf(await requestAndRead(sourceHarness.sockets.issuer, "198.18.1.1", quoteRequest)),
    429,
  );
  assert.equal(
    statusOf(await requestAndRead(sourceHarness.sockets.issuer, "198.18.1.2", quoteRequest)),
    200,
  );
  assert.equal(sourceHarness.lanes.issuer.records.length, 7);

  const globalHarness = await createHarness(t);
  for (let index = 0; index < 60; index += 1) {
    const source = `198.19.${Math.floor(index / 250)}.${(index % 250) + 1}`;
    assert.equal(
      statusOf(await requestAndRead(globalHarness.sockets.issuer, source, quoteRequest)),
      200,
    );
  }
  assert.equal(
    statusOf(await requestAndRead(globalHarness.sockets.issuer, "198.19.1.1", quoteRequest)),
    429,
  );
  assert.equal(globalHarness.lanes.issuer.records.length, 60);
});

test("HAProxy publisher lane admits only the exact private-route source", {
  skip: HAPROXY === undefined,
}, async (t) => {
  const harness = await createHarness(t);
  assert.equal(
    statusOf(
      await requestAndRead(
        harness.sockets.directoryPublisher,
        "198.20.0.2",
        directoryPublisherRequest,
      ),
    ),
    403,
  );
  assert.equal(harness.lanes.directoryPublisher.records.length, 0);
  assert.equal(
    statusOf(
      await requestAndRead(
        harness.sockets.directoryPublisher,
        "198.20.0.1",
        directoryPublisherRequest,
      ),
    ),
    200,
  );
  assert.equal(harness.lanes.directoryPublisher.records.length, 1);
});

test("HAProxy publisher lane uses PROXY v2 to admit only the exact IPv6 ULA source", {
  skip: HAPROXY === undefined,
}, async (t) => {
  const publisherClientIp = "fd42:6270:6972:1::1";
  const harness = await createHarness(t, { publisherClientIp });
  assert.equal(
    statusOf(
      await requestAndRead(
        harness.sockets.directoryPublisher,
        "fd42:6270:6972:1::2",
        directoryPublisherRequest,
      ),
    ),
    403,
  );
  assert.equal(harness.lanes.directoryPublisher.records.length, 0);
  assert.equal(
    statusOf(
      await requestAndRead(
        harness.sockets.directoryPublisher,
        publisherClientIp,
        directoryPublisherRequest,
      ),
    ),
    200,
  );
  assert.equal(harness.lanes.directoryPublisher.records.length, 1);
});

test("HAProxy strips source, auth, and correlation material before business services", {
  skip: HAPROXY === undefined,
}, async (t) => {
  const harness = await createHarness(t);
  const sourceIp = "203.0.113.77";
  const request = [
    "POST /v1/quotes/abc/status HTTP/1.1",
    "Host: pay.example.net",
    "Content-Length: 0",
    "Connection: close",
    `Forwarded: for=${sourceIp}`,
    `X-Forwarded-For: ${sourceIp}`,
    `X-Original-Forwarded-For: ${sourceIp}`,
    `X-Real-IP: ${sourceIp}`,
    `CF-Connecting-IP: ${sourceIp}`,
    `True-Client-IP: ${sourceIp}`,
    `X-Client-IP: ${sourceIp}`,
    `X-Envoy-External-Address: ${sourceIp}`,
    "X-Request-ID: invoice-query-link",
    "X-Correlation-ID: invoice-query-link",
    "Traceparent: 00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    "Tracestate: vendor=value",
    "Baggage: invoice=secret",
    "Authorization: Bearer payer-identity",
    "Proxy-Authorization: Basic payer-identity",
    "Cookie: invoice=secret",
    "Via: identifying-proxy",
    "",
    "",
  ].join("\r\n");
  assert.equal(statusOf(await requestAndRead(harness.sockets.issuer, sourceIp, request)), 200);
  assert.equal(harness.lanes.issuer.records.length, 1);
  const observed = harness.lanes.issuer.records[0];
  assert.equal(observed.remoteAddress, "127.0.0.1");
  assert.equal(observed.raw.startsWith("POST "), true);
  assert.equal(observed.raw.includes(sourceIp), false);
  for (const forbidden of [
    "forwarded:",
    "x-forwarded-",
    "cf-connecting-ip:",
    "true-client-ip:",
    "x-client-ip:",
    "x-envoy-external-address:",
    "x-original-forwarded-for:",
    "x-real-ip:",
    "x-request-id:",
    "x-correlation-id:",
    "traceparent:",
    "tracestate:",
    "baggage:",
    "authorization:",
    "proxy-authorization:",
    "cookie:",
    "via:",
  ]) {
    assert.equal(observed.raw.toLowerCase().includes(forbidden), false, forbidden);
  }
});

async function unusedTcpPort(host = "127.0.0.1") {
  const server = net.createServer();
  const address = await listen(server, host);
  await closeServer(server);
  return address.port;
}

function waitForTcpListener(
  port,
  child,
  output,
  timeoutMs = 5_000,
  host = "127.0.0.1",
) {
  const started = Date.now();
  return new Promise((resolvePromise, rejectPromise) => {
    const attempt = () => {
      if (child.exitCode !== null) {
        rejectPromise(new Error(`Caddy exited before listener readiness: ${output()}`));
        return;
      }
      const probe = net.createConnection({ host, port });
      probe.once("connect", () => {
        probe.destroy();
        resolvePromise();
      });
      probe.once("error", (error) => {
        probe.destroy();
        if (Date.now() - started > timeoutMs) {
          rejectPromise(new Error(`timed out waiting for Caddy listener: ${error.message}`));
          return;
        }
        setTimeout(attempt, 10);
      });
    };
    attempt();
  });
}

function plainHttpRequest(
  port,
  localAddress,
  request = providerRequest,
  host = "127.0.0.1",
) {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = net.createConnection({ host, port, localAddress });
    let bytes = "";
    socket.on("connect", () => {
      socket.write(request);
    });
    socket.on("data", (chunk) => { bytes += chunk.toString("latin1"); });
    socket.on("end", () => resolvePromise(bytes));
    socket.on("error", rejectPromise);
  });
}

function httpResponseHeaders(socket, readyEvent, request, label, timeoutMs = 5_000) {
  return new Promise((resolvePromise, rejectPromise) => {
    let bytes = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      rejectPromise(new Error(`timed out reading HTTP response headers from ${label}`));
    }, timeoutMs);
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      rejectPromise(error);
    };
    socket.once(readyEvent, () => socket.write(request));
    socket.on("data", (chunk) => {
      bytes += chunk.toString("latin1");
      if (!bytes.includes("\r\n\r\n") || settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolvePromise(bytes);
    });
    socket.once("end", () => fail(new Error(`HTTP response ended before complete headers from ${label}`)));
    socket.once("error", fail);
  });
}

function tlsHttpResponseHeaders(port, localAddress, request, host, servername) {
  const socket = tls.connect({
    host,
    port,
    localAddress,
    rejectUnauthorized: false,
    servername,
  });
  return httpResponseHeaders(
    socket,
    "secureConnect",
    request,
    `${localAddress}->${host}:${port} SNI=${servername}`,
  );
}

function nonLoopbackIpv4Address() {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (!entry.internal && (entry.family === "IPv4" || entry.family === 4)) {
        return entry.address;
      }
    }
  }
  return undefined;
}

test("the selected Caddy binary enforces the exact publisher source address", {
  skip: CADDY === undefined,
}, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-caddy-publisher-source-"));
  chmodSync(directory, 0o700);
  const port = await unusedTcpPort();
  const caddyfile = join(directory, "Caddyfile");
  writeFileSync(caddyfile, `{
  admin off
  persist_config off
  auto_https off
}

http://:${port} {
  bind 0.0.0.0
  @publisher {
    remote_ip 127.0.0.1
    method GET
    path /v1/directory
    header Host publisher.example.net
  }
  handle @publisher {
    respond "ok" 200
  }
  handle {
    respond "" 404
  }
}
`, { mode: 0o600 });
  const validation = spawnSync(CADDY, ["validate", "--config", caddyfile, "--adapter", "caddyfile"], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(validation.status, 0, `${validation.stdout}\n${validation.stderr}`);
  const caddy = spawn(CADDY, ["run", "--config", caddyfile, "--adapter", "caddyfile"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  caddy.stdout.on("data", (chunk) => { output += chunk; });
  caddy.stderr.on("data", (chunk) => { output += chunk; });
  t.after(async () => {
    await stopProcess(caddy);
    rmSync(directory, { force: true, recursive: true });
  });
  await waitForTcpListener(port, caddy, () => output);

  const request =
    "GET /v1/directory HTTP/1.1\r\nHost: publisher.example.net\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: close\r\n\r\n";
  const unauthorizedAddress = nonLoopbackIpv4Address();
  assert.ok(unauthorizedAddress, "test host has no non-loopback IPv4 address");
  assert.equal(
    statusOf(
      await plainHttpRequest(port, unauthorizedAddress, request, unauthorizedAddress),
    ),
    404,
  );
  assert.equal(statusOf(await plainHttpRequest(port, "127.0.0.1", request)), 200);
});

test("the selected Caddy binary removes source headers before PROXY v2 Unix handoff", {
  skip: CADDY === undefined,
}, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "bpir-caddy-source-strip-"));
  chmodSync(directory, 0o700);
  const upstreamPath = join(directory, "upstream.sock");
  const upstream = proxyV2BackendServer();
  await listenUnix(upstream.server, upstreamPath);
  const port = await unusedTcpPort();
  const caddyfile = join(directory, "Caddyfile");
  writeFileSync(caddyfile, `{
  admin off
  persist_config off
  auto_https off
}

http://:${port} {
  bind 127.0.0.1
  reverse_proxy unix/${upstreamPath} {
    header_up -*
    header_up Host pir.example.net
    transport http {
      versions 1.1
      proxy_protocol v2
      dial_timeout 3s
      response_header_timeout 3s
      keepalive off
      compression off
    }
  }
}
`, { mode: 0o600 });
  const validation = spawnSync(CADDY, ["validate", "--config", caddyfile, "--adapter", "caddyfile"], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(validation.status, 0, `${validation.stdout}\n${validation.stderr}`);
  const caddy = spawn(CADDY, ["run", "--config", caddyfile, "--adapter", "caddyfile"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  caddy.stdout.on("data", (chunk) => { output += chunk; });
  caddy.stderr.on("data", (chunk) => { output += chunk; });
  t.after(async () => {
    await stopProcess(caddy);
    upstream.destroySockets();
    await closeServer(upstream.server);
    rmSync(directory, { force: true, recursive: true });
  });
  await waitForTcpListener(port, caddy, () => output);

  const sourceMarker = "198.51.100.92";
  const response = await plainHttpRequest(port, "127.0.0.1", [
    "GET /v1/pir HTTP/1.1",
    "Host: public.example.net",
    `Forwarded: for=${sourceMarker}`,
    `X-Forwarded-For: ${sourceMarker}`,
    `X-Real-IP: ${sourceMarker}`,
    `CF-Connecting-IP: ${sourceMarker}`,
    `True-Client-IP: ${sourceMarker}`,
    "X-Request-ID: source-query-link",
    "Connection: close",
    "",
    "",
  ].join("\r\n"));
  assert.equal(statusOf(response), 200);
  await waitFor(() => upstream.records.length === 1, "Caddy protected Unix handoff");
  const observed = upstream.records[0];
  assert.equal(observed.error, undefined);
  assert.equal(observed.sourceAddress, "127.0.0.1");
  assert.equal(observed.raw.includes(sourceMarker), false);
  assert.equal(observed.raw.includes("127.0.0.1"), false);
  for (const forbidden of [
    "forwarded:",
    "x-forwarded-",
    "x-real-ip:",
    "cf-connecting-ip:",
    "true-client-ip:",
    "x-request-id:",
  ]) {
    assert.equal(observed.raw.toLowerCase().includes(forbidden), false, forbidden);
  }
});

test("the selected Caddy binary sends PROXY v2 over the protected Unix socket", {
  skip: HAPROXY === undefined || CADDY === undefined,
}, async (t) => {
  const harness = await createHarness(t);
  const port = await unusedTcpPort();
  const caddyfile = join(harness.directory, "Caddyfile");
  writeFileSync(caddyfile, `{
  admin off
  persist_config off
  auto_https off
}

http://:${port} {
  bind 127.0.0.1
  reverse_proxy unix/${harness.sockets.provider} {
    header_up -*
    header_up Host pir.example.net
    transport http {
      versions 1.1
      proxy_protocol v2
      dial_timeout 3s
      response_header_timeout 3s
      keepalive off
      compression off
    }
  }
}
`, { mode: 0o600 });
  const validation = spawnSync(CADDY, ["validate", "--config", caddyfile, "--adapter", "caddyfile"], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(
    validation.status,
    0,
    `Caddy lacks reviewed Unix+PROXY-v2 support:\n${validation.stdout}\n${validation.stderr}`,
  );
  const caddy = spawn(CADDY, ["run", "--config", caddyfile, "--adapter", "caddyfile"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  caddy.stdout.on("data", (chunk) => { output += chunk; });
  caddy.stderr.on("data", (chunk) => { output += chunk; });
  t.after(() => stopProcess(caddy));
  await waitForTcpListener(port, caddy, () => output);
  const sourceMarker = "198.51.100.91";
  const response = await plainHttpRequest(port, "127.0.0.2", [
    "GET /v1/pir HTTP/1.1",
    "Host: public.example.net",
    `Forwarded: for=${sourceMarker}`,
    `X-Forwarded-For: ${sourceMarker}`,
    `X-Real-IP: ${sourceMarker}`,
    "X-Request-ID: source-query-link",
    "Connection: close",
    "",
    "",
  ].join("\r\n"));
  assert.equal(statusOf(response), 200);
  await waitFor(
    () => Object.values(harness.lanes).some((lane) => lane.records.length >= 1),
    "Caddy-to-HAProxy request",
  );
  assert.equal(
    harness.lanes.provider.records.length >= 1,
    true,
    JSON.stringify(
      Object.fromEntries(
        Object.entries(harness.lanes).map(([name, lane]) => [name, lane.records.length]),
      ),
    ),
  );
  const observed = harness.lanes.provider.records.at(-1);
  assert.equal(observed.remoteAddress, "127.0.0.1");
  assert.equal(observed.raw.includes("127.0.0.2"), false);
  assert.equal(observed.raw.includes(sourceMarker), false);
  for (const forbidden of [
    "forwarded:",
    "x-forwarded-",
    "x-real-ip:",
    "x-request-id:",
  ]) {
    assert.equal(observed.raw.toLowerCase().includes(forbidden), false, forbidden);
  }
});

function renderedCaddyLaneHarnessConfig(
  harness,
  { certificate, edgePort, key, publisherClientIp },
) {
  const publicHosts = [
    ["@PROVIDER_WSS_HOST@", "pir.example.net"],
    ["@PAYMENT_ISSUER_HTTPS_HOST@", "pay.example.net"],
    ["@DIRECTORY_RELAY_WSS_HOST@", "directory.example.net"],
  ];
  const publisherHost = "publisher.example.net";
  let rendered = readFileSync(CADDY_TEMPLATE, "utf8")
    .replace("servers :443", `servers :${edgePort}`)
    .replace("https://:443 {", `https://:${edgePort} {`)
    .replaceAll("@PUBLIC_HTTPS_BIND@", "127.0.0.1")
    .replaceAll("@DIRECTORY_PUBLISHER_PRIVATE_BIND@", "127.0.0.2")
    .replaceAll("@DIRECTORY_PUBLISHER_CLIENT_IP@", publisherClientIp)
    .replaceAll("@DIRECTORY_PUBLISHER_HTTPS_HOST@", publisherHost)
    .replaceAll("/run/bitcoinpir-source-fair-edge", harness.directory)
    .replaceAll(
      "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
      certificate,
    )
    .replaceAll(
      "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
      key,
    )
    .replaceAll("\tbind 127.0.0.1\n", `\tbind 127.0.0.1\n\ttls ${certificate} ${key}\n`);
  for (const [placeholder, host] of publicHosts) {
    rendered = rendered
      .replaceAll(placeholder, host)
      .replace(`${host} {`, `https://${host}:${edgePort} {`);
  }
  rendered = rendered.replace(
    `${publisherHost} {`,
    `https://${publisherHost}:${edgePort} {`,
  );
  assert.doesNotMatch(rendered, /@[A-Z][A-Z0-9_]+@/u);
  return rendered;
}

function websocketDirectoryRequest(host, extraHeaders = []) {
  return [
    "GET /v1/directory HTTP/1.1",
    `Host: ${host}`,
    "Connection: Upgrade",
    "Upgrade: websocket",
    "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    ...extraHeaders,
    "",
    "",
  ].join("\r\n");
}

test("complete rendered Caddy and HAProxy keep public and publisher relay lanes non-interchangeable", {
  skip: HAPROXY === undefined || CADDY === undefined || OPENSSL === undefined,
}, async (t) => {
  const publisherClientIp = "127.0.0.3";
  const unauthorizedPublisherIp = "127.0.0.4";
  const publicClientIp = "127.0.0.5";
  const harness = await createHarness(t, { publisherClientIp });
  const edgePort = await unusedTcpPort("127.0.0.1");
  const privatePortProbe = net.createServer();
  await listen(privatePortProbe, "127.0.0.2", edgePort);
  await closeServer(privatePortProbe);
  const certificate = join(harness.directory, "rendered-edge.crt");
  const key = join(harness.directory, "rendered-edge.key");
  const generated = spawnSync(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key,
    "-out", certificate,
    "-days", "1",
    "-subj", "/CN=publisher.example.net",
    "-addext", "subjectAltName=DNS:pir.example.net,DNS:pay.example.net,DNS:directory.example.net,DNS:publisher.example.net",
  ], { encoding: "utf8", shell: false });
  assert.equal(generated.status, 0, generated.stderr);
  const caddyfile = join(harness.directory, "rendered-public.Caddyfile");
  writeFileSync(
    caddyfile,
    renderedCaddyLaneHarnessConfig(harness, {
      certificate,
      edgePort,
      key,
      publisherClientIp,
    }),
    { mode: 0o600 },
  );
  const validation = spawnSync(CADDY, [
    "validate", "--config", caddyfile, "--adapter", "caddyfile",
  ], { encoding: "utf8", shell: false });
  assert.equal(
    validation.status,
    0,
    `complete rendered Caddy lane config failed validation:\n${validation.stdout}\n${validation.stderr}`,
  );
  assertRenderedCaddyJsonClosure(caddyfile, harness, edgePort);

  const caddy = spawn(CADDY, ["run", "--config", caddyfile, "--adapter", "caddyfile"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  caddy.stdout.on("data", (chunk) => { output += chunk; });
  caddy.stderr.on("data", (chunk) => { output += chunk; });
  t.after(() => stopProcess(caddy));
  await waitForTcpListener(edgePort, caddy, () => output);
  await waitForTcpListener(edgePort, caddy, () => output, 5_000, "127.0.0.2");

  const publicRequest = websocketDirectoryRequest("directory.example.net");
  assert.equal(
    statusOf(
      await tlsHttpResponseHeaders(
        edgePort,
        publicClientIp,
        publicRequest,
        "127.0.0.1",
        "directory.example.net",
      ),
    ),
    200,
  );
  await waitFor(
    () => harness.lanes.directoryPublic.records.length === 1,
    "rendered public-directory backend request",
  );
  assert.deepEqual(laneRecordCounts(harness), {
    directoryPublic: 1,
    directoryPublisher: 0,
    issuer: 0,
    provider: 0,
  });

  const publisherRequest = websocketDirectoryRequest("publisher.example.net");
  let before = laneRecordCounts(harness);
  const publicBindPublisherStatus = statusOf(
    await tlsHttpResponseHeaders(
      edgePort,
      publicClientIp,
      publisherRequest,
      "127.0.0.1",
      "publisher.example.net",
    ),
  );
  assert.equal(publicBindPublisherStatus >= 400 && publicBindPublisherStatus < 500, true);
  assert.deepEqual(laneRecordCounts(harness), before);

  before = laneRecordCounts(harness);
  const privateBindDirectoryStatus = statusOf(
    await tlsHttpResponseHeaders(
      edgePort,
      publisherClientIp,
      publicRequest,
      "127.0.0.2",
      "directory.example.net",
    ),
  );
  assert.equal(privateBindDirectoryStatus >= 400 && privateBindDirectoryStatus < 500, true);
  assert.deepEqual(laneRecordCounts(harness), before);

  const spoofedPublisherRequest = websocketDirectoryRequest("publisher.example.net", [
    `Forwarded: for=${publisherClientIp}`,
    `X-Forwarded-For: ${publisherClientIp}`,
  ]);
  before = laneRecordCounts(harness);
  const spoofedPublisherStatus = statusOf(
    await tlsHttpResponseHeaders(
      edgePort,
      unauthorizedPublisherIp,
      spoofedPublisherRequest,
      "127.0.0.2",
      "publisher.example.net",
    ),
  );
  assert.equal(spoofedPublisherStatus >= 400 && spoofedPublisherStatus < 500, true);
  assert.deepEqual(laneRecordCounts(harness), before);

  assert.equal(
    statusOf(
      await tlsHttpResponseHeaders(
        edgePort,
        publisherClientIp,
        publisherRequest,
        "127.0.0.2",
        "publisher.example.net",
      ),
    ),
    200,
  );
  await waitFor(
    () => harness.lanes.directoryPublisher.records.length === 1,
    "rendered publisher backend request",
  );
  assert.deepEqual(laneRecordCounts(harness), {
    directoryPublic: 1,
    directoryPublisher: 1,
    issuer: 0,
    provider: 0,
  });
  await stopProcess(caddy);
});
