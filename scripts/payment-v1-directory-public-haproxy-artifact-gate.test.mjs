import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  inspectStaticElf64X8664,
  validateBuildManifestV1,
  validateClosedHaproxyConfigV1,
  verifyArtifactClosureV1,
} from "./payment-v1-directory-public-haproxy-artifact-gate.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(SCRIPT_DIRECTORY, "..");
const GATE = join(SCRIPT_DIRECTORY, "payment-v1-directory-public-haproxy-artifact-gate.mjs");
const CONFIG = join(
  REPOSITORY,
  "deploy/payment-v1/edge/directory-public-haproxy.cfg.in",
);
const MANIFEST_TEMPLATE = join(
  REPOSITORY,
  "deploy/payment-v1/edge/directory-public-haproxy-build-manifest.json.in",
);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function staticElf(programType = 1) {
  const bytes = Buffer.alloc(64 + 56);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46]).copy(bytes, 0);
  bytes[4] = 2;
  bytes[5] = 1;
  bytes[6] = 1;
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(1, 56);
  bytes.writeUInt32LE(programType, 64);
  return bytes;
}

function fixture(t, { programType = 1 } = {}) {
  const root = mkdtempSync(join(tmpdir(), "bpir-directory-public-haproxy-"));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const binary = staticElf(programType);
  const digest = sha256(binary);
  const manifest = readFileSync(MANIFEST_TEMPLATE, "utf8")
    .replaceAll("@HAPROXY_SHA256@", digest);
  const paths = {
    binary: join(root, "haproxy"),
    config: join(root, "haproxy.cfg"),
    manifest: join(root, "build-manifest.json"),
  };
  writeFileSync(paths.binary, binary, { mode: 0o555 });
  writeFileSync(paths.config, readFileSync(CONFIG), { mode: 0o440 });
  writeFileSync(paths.manifest, manifest, { mode: 0o444 });
  return { digest, manifest: JSON.parse(manifest), paths };
}

test("static artifact gate accepts the exact manifest, ELF and closed config", (t) => {
  const subject = fixture(t);
  assert.equal(validateBuildManifestV1(subject.manifest), subject.digest);
  inspectStaticElf64X8664(readFileSync(subject.paths.binary));
  validateClosedHaproxyConfigV1(readFileSync(subject.paths.config, "utf8"));
  assert.deepEqual(verifyArtifactClosureV1({
    binaryPath: subject.paths.binary,
    configPath: subject.paths.config,
    manifestPath: subject.paths.manifest,
  }), {
    artifact_sha256: subject.digest,
    config_sha256: sha256(readFileSync(subject.paths.config)),
    manifest_sha256: sha256(readFileSync(subject.paths.manifest)),
  });
  const cli = spawnSync(process.execPath, [
    GATE,
    "verify",
    "--manifest", subject.paths.manifest,
    "--binary", subject.paths.binary,
    "--config", subject.paths.config,
  ], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).result, "PASS");
});

for (const [type, label] of [[2, "PT_DYNAMIC"], [3, "PT_INTERP"]]) {
  test(`static artifact gate rejects ${label}`, (t) => {
    const subject = fixture(t, { programType: type });
    assert.throws(
      () => verifyArtifactClosureV1({
        binaryPath: subject.paths.binary,
        configPath: subject.paths.config,
        manifestPath: subject.paths.manifest,
      }),
      new RegExp(label, "u"),
    );
  });
}

test("build manifest rejects source, compiler, options and reproducibility drift", (t) => {
  const subject = fixture(t);
  for (const [mutate, expected] of [
    [(value) => { value.source.archive_sha256 = "0".repeat(64); }, /source/u],
    [(value) => { value.compiler.version = "14.0.0"; }, /GCC 13\.3\.0/u],
    [(value) => { value.build.enabled_options.pop(); }, /enabled_options/u],
    [(value) => { value.disabled_options = value.disabled_options.filter((entry) => entry !== "USE_SYSTEMD"); }, /disabled_options/u],
    [(value) => { value.build.independent_build_sha256[1] = "0".repeat(64); }, /independent build digests/u],
  ]) {
    const value = structuredClone(subject.manifest);
    mutate(value);
    assert.throws(() => validateBuildManifestV1(value), expected);
  }
});

test("closed HAProxy config rejects every unreviewed section and directive", () => {
  const base = readFileSync(CONFIG, "utf8");
  const mutations = [
    ["hostname backend", (value) => value.replace("127.0.0.1:8080", "relay.internal:8080")],
    ["second bind", (value) => value.replace(
      "    maxconn 48",
      "    bind 127.0.0.1:18080\n    maxconn 48",
    )],
    ["source header reinjection", (value) => value.replace(
      "    default_backend directory_public_application",
      "    http-request set-header X-Real-IP %[src]\n    default_backend directory_public_application",
    )],
    ["forwarded-for reinjection", (value) => value.replace(
      "    default_backend directory_public_application",
      "    http-request set-header X-Forwarded-For %[src]\n    default_backend directory_public_application",
    )],
    ["automatic forwardfor", (value) => value.replace(
      "    option http-no-delay",
      "    option http-no-delay\n    option forwardfor",
    )],
    ["backend PROXY protocol", (value) => value.replace(
      "127.0.0.1:8080 maxconn 48",
      "127.0.0.1:8080 send-proxy maxconn 48",
    )],
    ["logging", (value) => value.replace("    maxconn 64", "    log stdout format raw local0\n    maxconn 64")],
    ["stats socket", (value) => value.replace(
      "    maxconn 64",
      "    stats socket /run/haproxy-admin.sock mode 600 level admin\n    maxconn 64",
    )],
    ["extra server", (value) => value.replace(
      "    server directory-public 127.0.0.1:8080 maxconn 48",
      "    server directory-public 127.0.0.1:8080 maxconn 48\n    server shadow 127.0.0.1:8081",
    )],
    ["unreviewed request rule", (value) => value.replace(
      "    default_backend directory_public_application",
      "    http-request set-header X-Unreviewed fixed\n    default_backend directory_public_application",
    )],
    ["resolver section", (value) => `${value}\nresolvers ambient_dns\n    nameserver dns 127.0.0.53:53\n`],
    ["Lua loader", (value) => value.replace("    maxconn 64", "    lua-load /tmp/evil.lua\n    maxconn 64")],
    ["dynamic server", (value) => value.replace(
      "    server directory-public 127.0.0.1:8080 maxconn 48",
      "    server-template app 1-2 relay.internal:8080",
    )],
    ["module loader", (value) => value.replace("    maxconn 64", "    dlopen /tmp/evil.so\n    maxconn 64")],
    ["duplicate section", (value) => `${value}\nfrontend directory_public\n    maxconn 48\n`],
    ["reordered sections", (value) => {
      const sources = "backend directory_public_sources\n    stick-table type ipv6 size 4096 expire 2m nopurge store conn_cur,conn_rate(10s),bytes_out_rate(1s)\n\n";
      return value.replace(sources, "").replace(
        "backend directory_public_application\n",
        `${sources}backend directory_public_application\n`,
      );
    }],
  ];
  for (const [label, mutate] of mutations) {
    assert.throws(
      () => validateClosedHaproxyConfigV1(mutate(base)),
      /reviewed section|section order|directives/u,
      label,
    );
  }
});

test("closed HAProxy config preserves only semantic whitespace and comments", () => {
  const base = readFileSync(CONFIG, "utf8");
  const equivalent = base.replace(
    "    maxconn 64",
    "\tmaxconn\t64    # semantically inert reviewed comment",
  );
  assert.doesNotThrow(() => validateClosedHaproxyConfigV1(equivalent));
  for (const mutated of [
    base.replace("global\n", "defaults\n"),
    `${base}\nbackend directory_public_application\n    http-reuse never\n`,
  ]) {
    assert.throws(() => validateClosedHaproxyConfigV1(mutated), /section order/u);
  }
});

test("artifact closure rejects digest drift, symlinks and hard links", (t) => {
  const subject = fixture(t);
  chmodSync(subject.paths.binary, 0o755);
  writeFileSync(subject.paths.binary, Buffer.concat([readFileSync(subject.paths.binary), Buffer.from([0])]));
  chmodSync(subject.paths.binary, 0o555);
  assert.throws(
    () => verifyArtifactClosureV1({
      binaryPath: subject.paths.binary,
      configPath: subject.paths.config,
      manifestPath: subject.paths.manifest,
    }),
    /digest differs/u,
  );

  const symlinkRoot = join(dirname(subject.paths.binary), "symlink-root");
  mkdirSync(symlinkRoot);
  const symlink = join(symlinkRoot, "manifest.json");
  symlinkSync(subject.paths.manifest, symlink);
  assert.throws(
    () => verifyArtifactClosureV1({
      binaryPath: subject.paths.binary,
      configPath: subject.paths.config,
      manifestPath: symlink,
    }),
    /regular non-symlink/u,
  );

  chmodSync(subject.paths.binary, 0o755);
  writeFileSync(subject.paths.binary, staticElf());
  chmodSync(subject.paths.binary, 0o555);
  const hardlink = join(symlinkRoot, "config.cfg");
  linkSync(subject.paths.config, hardlink);
  assert.throws(
    () => verifyArtifactClosureV1({
      binaryPath: subject.paths.binary,
      configPath: subject.paths.config,
      manifestPath: subject.paths.manifest,
    }),
    /single-link regular/u,
  );
});
