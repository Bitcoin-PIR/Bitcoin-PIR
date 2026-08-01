#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, openSync } from "node:fs";
import tls from "node:tls";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  canonicalJson,
  parseStrictJson,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";

const PROBE_PATH =
  "/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs";
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const EXPECTED_EXEC_ARGV_PREFIX = Object.freeze([
  "--no-expose-wasm",
  "--jitless",
  "--use-openssl-ca",
  "--no-warnings",
  "--experimental-vm-modules",
  "--input-type=module",
  "--eval",
]);

function fail(message) {
  throw new Error(`publisher-private-health-probe: ${message}`);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    fail(`${label} keys must equal ${canonicalJson(wanted).trim()}`);
  }
}

function validateCheck(check) {
  exactKeys(check, [
    "connect_ip",
    "expected_body_sha256",
    "expected_status",
    "host",
    "kind",
    "lane",
    "leaf_certificate_sha256",
    "max_response_bytes",
    "network_namespace",
    "path",
    "timeout_ms",
  ], "health check");
  if (
    check.connect_ip !== "10.203.0.1" ||
    check.expected_body_sha256 !== null ||
    check.expected_status !== 101 ||
    check.kind !== "websocket-upgrade" ||
    check.lane !== "directory-publisher" ||
    check.network_namespace !== "bpir-directory-publisher" ||
    check.path !== "/" ||
    typeof check.host !== "string" ||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(check.host) ||
    typeof check.leaf_certificate_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(check.leaf_certificate_sha256) ||
    !Number.isSafeInteger(check.max_response_bytes) ||
    check.max_response_bytes < 1 || check.max_response_bytes > 262_144 ||
    !Number.isSafeInteger(check.timeout_ms) ||
    check.timeout_ms < 100 || check.timeout_ms > 30_000
  ) {
    fail("health check differs from the reviewed namespace-only WebSocket shape");
  }
}

function namespaceIdentity() {
  const fd = openSync("/proc/self/ns/net", constants.O_RDONLY | constants.O_CLOEXEC);
  try {
    const stat = fstatSync(fd, { bigint: true });
    return { device: stat.dev.toString(), inode: stat.ino.toString() };
  } finally {
    closeSync(fd);
  }
}

export function parsePublisherPrivateWebSocketResponse(bytes, websocketKey) {
  const headerEnd = bytes.indexOf("\r\n\r\n");
  if (headerEnd < 0) return null;
  if (bytes.length !== headerEnd + 4) {
    fail("WebSocket upgrade returned unexpected bytes after its headers");
  }
  const head = bytes.subarray(0, headerEnd).toString("latin1");
  if (!/^[\x09\x20-\x7e\r\n]*$/u.test(head)) {
    fail("WebSocket response headers contain forbidden bytes");
  }
  const lines = head.split("\r\n");
  if (lines.some((line) => line.includes("\r") || line.includes("\n"))) {
    fail("WebSocket response contains a bare carriage return or line feed");
  }
  if (lines.shift() !== "HTTP/1.1 101 Switching Protocols") {
    fail("publisher ingress did not return HTTP/1.1 101");
  }
  const headers = new Map();
  for (const line of lines) {
    if (line.startsWith(" ") || line.startsWith("\t")) {
      fail("WebSocket response uses obsolete header folding");
    }
    const separator = line.indexOf(":");
    if (separator < 1) fail("WebSocket response contains a malformed header");
    const name = line.slice(0, separator).toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(name) || headers.has(name)) {
      fail("WebSocket response contains duplicate or malformed headers");
    }
    headers.set(name, line.slice(separator + 1).trim());
  }
  const connection = (headers.get("connection") ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase());
  if (!connection.includes("upgrade") || headers.get("upgrade")?.toLowerCase() !== "websocket") {
    fail("publisher ingress did not complete a WebSocket upgrade");
  }
  const expectedAccept = createHash("sha1")
    .update(`${websocketKey}${WS_GUID}`, "ascii")
    .digest("base64");
  if (headers.get("sec-websocket-accept") !== expectedAccept) {
    fail("publisher ingress returned the wrong Sec-WebSocket-Accept");
  }
  if (headers.has("content-length") || headers.has("transfer-encoding")) {
    fail("WebSocket upgrade returned an unexpected body framing header");
  }
  if (headers.has("sec-websocket-protocol") || headers.has("sec-websocket-extensions")) {
    fail("WebSocket upgrade selected an unrequested protocol or extension");
  }
  return true;
}

export function probePublisherPrivateIngress(check) {
  validateCheck(check);
  return new Promise((resolvePromise, rejectPromise) => {
    let response = Buffer.alloc(0);
    let settled = false;
    let socket;
    const websocketKey = randomBytes(16).toString("base64");
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      if (error) rejectPromise(error);
      else resolvePromise(value);
    };
    const timer = setTimeout(
      () => finish(new Error("publisher private health probe timed out")),
      check.timeout_ms,
    );
    socket = tls.connect({
      host: check.connect_ip,
      minVersion: "TLSv1.2",
      port: 443,
      rejectUnauthorized: true,
      servername: check.host,
    });
    socket.once("secureConnect", () => {
      if (!socket.authorized) {
        finish(new Error("publisher TLS chain or hostname was rejected"));
        return;
      }
      const certificate = socket.getPeerCertificate(true);
      if (!certificate?.raw) {
        finish(new Error("publisher TLS leaf certificate is missing"));
        return;
      }
      const leafCertificateSha256 = createHash("sha256")
        .update(certificate.raw)
        .digest("hex");
      if (leafCertificateSha256 !== check.leaf_certificate_sha256) {
        finish(new Error("publisher TLS leaf certificate drifted"));
        return;
      }
      socket.write([
        "GET / HTTP/1.1",
        `Host: ${check.host}`,
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Key: ${websocketKey}`,
        "User-Agent: bitcoinpir-payment-v1-health/1",
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > check.max_response_bytes) {
        finish(new Error("publisher health response exceeds its approved bound"));
        return;
      }
      try {
        if (parsePublisherPrivateWebSocketResponse(response, websocketKey) === null) return;
        finish(null, {
          body_sha256: null,
          leaf_certificate_sha256: check.leaf_certificate_sha256,
          status: 101,
          success: true,
        });
      } catch (error) {
        finish(error);
      }
    });
    socket.once("error", (error) => finish(error));
    socket.once("end", () => finish(new Error("publisher ingress closed before a valid upgrade")));
  });
}

function parseArgs(argv) {
  const args = [...argv];
  const command = args.shift();
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined || options.has(key)) {
      fail("arguments must be unique --name value pairs");
    }
    options.set(key, value);
  }
  return { command, options };
}

function required(options, key) {
  const value = options.get(key);
  if (value === undefined) fail(`missing ${key}`);
  return value;
}

async function main(argv) {
  if (
    process.platform !== "linux" || process.geteuid?.() !== 0 ||
    fileURLToPath(import.meta.url) !== PROBE_PATH ||
    process.execPath !== "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ||
    process.argv0 !== "/usr/bin/node" || process.argv[0] !== "/usr/bin/node" ||
    process.execArgv.length !== EXPECTED_EXEC_ARGV_PREFIX.length + 1 ||
    canonicalJson(process.execArgv.slice(0, -1)) !== canonicalJson(EXPECTED_EXEC_ARGV_PREFIX) ||
    typeof WebAssembly !== "undefined" ||
    canonicalJson(Object.fromEntries(Object.entries(process.env))) !== canonicalJson({
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PATH: "/usr/sbin:/usr/bin",
      TZ: "UTC",
    })
  ) {
    fail("probe is outside its root Linux launcher-pinned runtime boundary");
  }
  const { command, options } = parseArgs(argv);
  const expectedOptions = ["--check-base64", "--namespace-device", "--namespace-inode"];
  if (
    command !== "publisher-private-health-probe" ||
    canonicalJson([...options.keys()].sort()) !== canonicalJson(expectedOptions)
  ) {
    fail("usage: publisher-private-health-probe --namespace-device N --namespace-inode N --check-base64 BASE64");
  }
  const namespaceDevice = required(options, "--namespace-device");
  const namespaceInode = required(options, "--namespace-inode");
  if (!/^[1-9][0-9]*$/u.test(namespaceDevice) || !/^[1-9][0-9]*$/u.test(namespaceInode)) {
    fail("receipt-bound namespace identity is malformed");
  }
  const observedNamespace = namespaceIdentity();
  if (
    observedNamespace.device !== namespaceDevice ||
    observedNamespace.inode !== namespaceInode
  ) {
    fail("launcher did not enter the receipt-bound publisher namespace");
  }
  const encoded = required(options, "--check-base64");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) {
    fail("health check is not canonical base64");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length < 2 || bytes.length > 12 * 1024 || bytes.toString("base64") !== encoded) {
    fail("health check base64 is non-canonical or outside bounds");
  }
  const check = parseStrictJson(bytes.toString("utf8"), "publisher private health check");
  const result = await probePublisherPrivateIngress(check);
  process.stdout.write(canonicalJson(result));
}

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  await main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
