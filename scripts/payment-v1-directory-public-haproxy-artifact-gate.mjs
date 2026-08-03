#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const MAX_BINARY_BYTES = 32 * 1024 * 1024;
const MAX_TEXT_BYTES = 64 * 1024;
const EXPECTED_SOURCE = Object.freeze({
  archive_sha256:
    "88c28dae25ea46672e66f8db0dadd1fb5920e06ee2415ceb9f281c256b537727",
  archive_url: "https://www.haproxy.org/download/2.8/src/haproxy-2.8.26.tar.gz",
  version: "2.8.26",
});
const EXPECTED_ENABLED_OPTIONS = Object.freeze([
  "USE_ACCEPT4",
  "USE_EPOLL",
  "USE_LINUX_SPLICE",
  "USE_POLL",
  "USE_PRCTL",
  "USE_SHM_OPEN",
  "USE_TFO",
  "USE_THREAD",
  "USE_THREAD_DUMP",
]);
const EXPECTED_DISABLED_OPTIONS = Object.freeze([
  "USE_GETADDRINFO",
  "USE_LIBCRYPT",
  "USE_LUA",
  "USE_OPENSSL",
  "USE_SYSTEMD",
]);
const REVIEWED_HAPROXY_ENDPOINTS = Object.freeze({
  application: "127.0.0.1:8080",
  socket: "/run/bitcoinpir-directory-public-edge/directory-public.sock",
});
const EXPECTED_HAPROXY_SECTIONS = Object.freeze([
  Object.freeze({
    directives: Object.freeze([
      "maxconn 64",
      "hard-stop-after 10s",
      "zero-warning",
    ]),
    header: "global",
  }),
  Object.freeze({
    directives: Object.freeze([
      "mode http",
      "no log",
      "option http-server-close",
      "option http-no-delay",
      "timeout connect 3s",
      "timeout client 15s",
      "timeout client-fin 5s",
      "timeout server 15s",
      "timeout server-fin 5s",
      "timeout http-request 5s",
      "timeout http-keep-alive 1s",
      "timeout queue 3s",
      "timeout tunnel 300s",
    ]),
    header: "defaults",
  }),
  Object.freeze({
    directives: Object.freeze([
      "stick-table type ipv6 size 4096 expire 2m nopurge store conn_cur,conn_rate(10s),bytes_out_rate(1s)",
    ]),
    header: "backend directory_public_sources",
  }),
  Object.freeze({
    directives: Object.freeze([
      `bind ${REVIEWED_HAPROXY_ENDPOINTS.socket} accept-proxy mode 660`,
      "maxconn 48",
      "http-request deny deny_status 429 if { table_avl(directory_public_sources) eq 0 } !{ src,ipmask(32,64),in_table(directory_public_sources) }",
      "http-request track-sc0 src,ipmask(32,64) table directory_public_sources",
      "http-request deny deny_status 429 unless { sc0_tracked }",
      "http-request deny deny_status 429 if { sc0_conn_cur gt 4 }",
      "http-request deny deny_status 429 if { sc0_conn_rate gt 12 }",
      "http-request deny deny_status 429 unless { method GET }",
      "http-request deny deny_status 404 unless { path -m str / }",
      "http-request del-header Forwarded",
      "http-request del-header X-Forwarded-For",
      "http-request del-header X-Forwarded-Host",
      "http-request del-header X-Forwarded-Proto",
      "http-request del-header CF-Connecting-IP",
      "http-request del-header Client-IP",
      "http-request del-header Fastly-Client-IP",
      "http-request del-header Fly-Client-IP",
      "http-request del-header True-Client-IP",
      "http-request del-header X-Client-IP",
      "http-request del-header X-Cluster-Client-IP",
      "http-request del-header X-Envoy-External-Address",
      "http-request del-header X-Original-Client-IP",
      "http-request del-header X-Original-Forwarded-For",
      "http-request del-header X-Real-IP",
      "http-request del-header X-Request-ID",
      "http-request del-header X-Correlation-ID",
      "http-request del-header Traceparent",
      "http-request del-header Tracestate",
      "http-request del-header Baggage",
      "http-request del-header Via",
      "http-request del-header Proxy-Authorization",
      "http-request del-header Authorization",
      "http-request del-header Cookie",
      "http-response del-header Via",
      "http-response del-header Set-Cookie",
      "filter bwlim-out directory_public_source_egress key src,ipmask(32,64) table directory_public_sources limit 4m min-size 2896",
      "filter bwlim-out directory_public_stream_egress default-limit 2m default-period 1s min-size 2896",
      "http-request set-bandwidth-limit directory_public_source_egress",
      "http-request set-bandwidth-limit directory_public_stream_egress",
      "default_backend directory_public_application",
    ]),
    header: "frontend directory_public",
  }),
  Object.freeze({
    directives: Object.freeze([
      "http-reuse never",
      `server directory-public ${REVIEWED_HAPROXY_ENDPOINTS.application} maxconn 48`,
    ]),
    header: "backend directory_public_application",
  }),
]);

function fail(message) {
  throw new Error(message);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const result = Object.create(null);
    for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key]);
    return result;
  }
  return value;
}

function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value))}\n`;
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} keys must equal ${JSON.stringify(wanted)}`);
  }
}

function exactJson(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} must equal ${JSON.stringify(expected)}`);
  }
}

function statFingerprint(stat) {
  return [
    stat.dev,
    stat.ino,
    stat.mode,
    stat.nlink,
    stat.uid,
    stat.gid,
    stat.size,
    stat.mtimeNs,
    stat.ctimeNs,
  ].map(String).join(":");
}

function readBoundRegularFile(pathInput, label, maximumBytes) {
  const path = resolve(pathInput);
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    fail(`${label} must be a single-link regular non-symlink file`);
  }
  if (before.size < 1n || before.size > BigInt(maximumBytes)) {
    fail(`${label} size is outside the reviewed bound`);
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (statFingerprint(opened) !== statFingerprint(before)) {
      fail(`${label} changed across descriptor open`);
    }
    const bytes = readFileSync(descriptor);
    if (BigInt(bytes.length) !== opened.size) fail(`${label} had a short descriptor read`);
    const after = lstatSync(path, { bigint: true });
    if (statFingerprint(after) !== statFingerprint(opened)) {
      fail(`${label} changed during descriptor read`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseManifest(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("HAProxy build manifest must be UTF-8");
  }
  if (/\r|\0/u.test(text)) fail("HAProxy build manifest must use canonical LF JSON");
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    fail("HAProxy build manifest is not valid JSON");
  }
  if (canonicalJson(manifest) !== text) {
    fail("HAProxy build manifest must be canonical JSON with no duplicate or reordered keys");
  }
  return manifest;
}

export function validateBuildManifestV1(manifest) {
  exactKeys(
    manifest,
    ["artifact", "build", "compiler", "disabled_options", "schema_version", "source"],
    "HAProxy build manifest",
  );
  if (manifest.schema_version !== 1) fail("HAProxy build manifest schema_version must equal 1");
  exactKeys(
    manifest.artifact,
    ["architecture", "elf_class", "has_pt_dynamic", "has_pt_interp", "sha256"],
    "HAProxy build manifest artifact",
  );
  if (
    manifest.artifact.architecture !== "x86_64" ||
    manifest.artifact.elf_class !== "ELF64" ||
    manifest.artifact.has_pt_dynamic !== false ||
    manifest.artifact.has_pt_interp !== false ||
    !/^[0-9a-f]{64}$/u.test(manifest.artifact.sha256)
  ) {
    fail("HAProxy build manifest must bind one static x86_64 ELF64 artifact digest");
  }
  exactKeys(
    manifest.build,
    ["debug", "enabled_options", "independent_build_sha256", "target", "warnings_as_errors"],
    "HAProxy build manifest build",
  );
  if (
    manifest.build.debug !== false ||
    manifest.build.target !== "generic" ||
    manifest.build.warnings_as_errors !== true
  ) {
    fail("HAProxy build manifest must bind the reviewed generic non-debug Werror build");
  }
  exactJson(
    manifest.build.enabled_options,
    [...EXPECTED_ENABLED_OPTIONS],
    "HAProxy build manifest enabled_options",
  );
  exactJson(
    manifest.disabled_options,
    [...EXPECTED_DISABLED_OPTIONS],
    "HAProxy build manifest disabled_options",
  );
  exactJson(
    manifest.build.independent_build_sha256,
    [manifest.artifact.sha256, manifest.artifact.sha256],
    "HAProxy build manifest independent build digests",
  );
  exactKeys(manifest.compiler, ["family", "version"], "HAProxy build manifest compiler");
  if (manifest.compiler.family !== "gcc" || manifest.compiler.version !== "13.3.0") {
    fail("HAProxy build manifest must bind GCC 13.3.0");
  }
  exactKeys(manifest.source, ["archive_sha256", "archive_url", "version"], "HAProxy build manifest source");
  exactJson(manifest.source, EXPECTED_SOURCE, "HAProxy build manifest source");
  return manifest.artifact.sha256;
}

export function inspectStaticElf64X8664(bytes) {
  if (bytes.length < 64 || !bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    fail("HAProxy artifact is not an ELF file");
  }
  if (bytes[4] !== 2 || bytes[5] !== 1 || bytes[6] !== 1) {
    fail("HAProxy artifact must be little-endian ELF64 version 1");
  }
  if (bytes.readUInt16LE(18) !== 62) fail("HAProxy artifact must target x86_64");
  const programOffset = bytes.readBigUInt64LE(32);
  const programEntrySize = bytes.readUInt16LE(54);
  const programCount = bytes.readUInt16LE(56);
  if (programEntrySize < 56 || programCount < 1 || programCount > 1024) {
    fail("HAProxy artifact has an invalid program-header table");
  }
  const end = programOffset + BigInt(programEntrySize) * BigInt(programCount);
  if (programOffset < 64n || end > BigInt(bytes.length)) {
    fail("HAProxy artifact program-header table is out of bounds");
  }
  for (let index = 0; index < programCount; index += 1) {
    const offset = Number(programOffset + BigInt(index * programEntrySize));
    const type = bytes.readUInt32LE(offset);
    if (type === 2) fail("HAProxy artifact contains forbidden PT_DYNAMIC");
    if (type === 3) fail("HAProxy artifact contains forbidden PT_INTERP");
  }
}

export function validateClosedHaproxyConfigV1(text) {
  if (!/^[\t\n\x20-\x7e]*$/u.test(text) || /\r|\0/u.test(text)) {
    fail("directory-public HAProxy configuration must be canonical ASCII LF text");
  }
  const sections = [];
  let current;
  for (const [index, original] of text.split("\n").entries()) {
    if (original.trimStart().startsWith("#")) continue;
    const withoutComment = original.replace(/[ \t]+#.*$/u, "").trimEnd();
    if (withoutComment.trim() === "") continue;
    if (withoutComment.endsWith("\\")) {
      fail(`directory-public HAProxy configuration line ${index + 1} uses a continuation`);
    }
    if (!/^[ \t]/u.test(withoutComment)) {
      if (!/^(?:global|defaults|frontend [a-z0-9_]+|backend [a-z0-9_]+)$/u.test(withoutComment)) {
        fail(`directory-public HAProxy configuration line ${index + 1} is not a reviewed section`);
      }
      current = { directives: [], header: withoutComment };
      sections.push(current);
      continue;
    }
    if (current === undefined) {
      fail(`directory-public HAProxy configuration line ${index + 1} precedes its section`);
    }
    current.directives.push(withoutComment.trim().replace(/[ \t]+/gu, " "));
  }
  exactJson(
    sections.map((section) => section.header),
    EXPECTED_HAPROXY_SECTIONS.map((section) => section.header),
    "directory-public HAProxy section order",
  );
  for (let index = 0; index < EXPECTED_HAPROXY_SECTIONS.length; index += 1) {
    exactJson(
      sections[index].directives,
      [...EXPECTED_HAPROXY_SECTIONS[index].directives],
      `directory-public HAProxy ${EXPECTED_HAPROXY_SECTIONS[index].header} directives`,
    );
  }
}

export function verifyArtifactClosureV1({ binaryPath, configPath, manifestPath }) {
  const manifestBytes = readBoundRegularFile(
    manifestPath,
    "HAProxy build manifest",
    MAX_TEXT_BYTES,
  );
  const manifest = parseManifest(manifestBytes);
  const expectedArtifactSha256 = validateBuildManifestV1(manifest);
  const binaryBytes = readBoundRegularFile(binaryPath, "HAProxy artifact", MAX_BINARY_BYTES);
  if (sha256(binaryBytes) !== expectedArtifactSha256) {
    fail("HAProxy artifact digest differs from the build manifest");
  }
  inspectStaticElf64X8664(binaryBytes);
  const configBytes = readBoundRegularFile(
    configPath,
    "directory-public HAProxy configuration",
    MAX_TEXT_BYTES,
  );
  let configText;
  try {
    configText = new TextDecoder("utf-8", { fatal: true }).decode(configBytes);
  } catch {
    fail("directory-public HAProxy configuration must be UTF-8");
  }
  validateClosedHaproxyConfigV1(configText);
  return Object.freeze({
    artifact_sha256: expectedArtifactSha256,
    config_sha256: sha256(configBytes),
    manifest_sha256: sha256(manifestBytes),
  });
}

function parseCli(argv) {
  if (argv[0] !== "verify") {
    fail("usage: payment-v1-directory-public-haproxy-artifact-gate.mjs verify --manifest ABS --binary ABS --config ABS");
  }
  const values = Object.create(null);
  const allowed = new Set(["--manifest", "--binary", "--config"]);
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || value === undefined || values[flag] !== undefined) {
      fail(`invalid, repeated or missing CLI option: ${flag ?? "<missing>"}`);
    }
    if (!value.startsWith("/")) fail(`${flag} must be an absolute path`);
    values[flag] = value;
  }
  for (const flag of allowed) {
    if (values[flag] === undefined) fail(`missing required CLI option ${flag}`);
  }
  return values;
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  try {
    const values = parseCli(process.argv.slice(2));
    const result = verifyArtifactClosureV1({
      binaryPath: values["--binary"],
      configPath: values["--config"],
      manifestPath: values["--manifest"],
    });
    process.stdout.write(`${canonicalJson({ result: "PASS", ...result })}`);
  } catch (error) {
    process.stderr.write(`payment-v1-directory-public-haproxy-artifact-gate: FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
