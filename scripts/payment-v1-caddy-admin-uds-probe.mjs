#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";

const MAX_GATE_SOURCE_BYTES = 8 * 1024 * 1024;
const expectedGateSha256 = process.env.BPIR_ADMIN_GATE_SHA256;
if (!/^[0-9a-f]{64}$/u.test(expectedGateSha256 ?? "")) {
  throw new Error("BPIR_ADMIN_GATE_SHA256 must be one lowercase SHA-256 digest");
}
const gateChunks = [];
let gateSize = 0;
for await (const chunk of process.stdin) {
  gateSize += chunk.length;
  if (gateSize > MAX_GATE_SOURCE_BYTES) {
    throw new Error(`admin gate source exceeded ${MAX_GATE_SOURCE_BYTES} bytes`);
  }
  gateChunks.push(chunk);
}
if (gateSize === 0) throw new Error("admin gate source stdin was empty");
const gateSource = Buffer.concat(gateChunks);
const observedGateSha256 = createHash("sha256").update(gateSource).digest("hex");
if (observedGateSha256 !== expectedGateSha256) {
  throw new Error("admin gate source stdin did not match BPIR_ADMIN_GATE_SHA256");
}
new TextDecoder("utf-8", { fatal: true }).decode(gateSource);
const {
  MAX_ADAPTED_JSON_BYTES,
  canonicalizeAdaptedCaddyJson,
  sha256,
} = await import(`data:text/javascript;base64,${gateSource.toString("base64")}`);
if (
  !Number.isSafeInteger(MAX_ADAPTED_JSON_BYTES) ||
  MAX_ADAPTED_JSON_BYTES < 1 ||
  typeof canonicalizeAdaptedCaddyJson !== "function" ||
  typeof sha256 !== "function"
) {
  throw new Error("admin gate source did not export the exact probe interface");
}

const socketPath = "/run/bitcoinpir-caddy-admin/admin.sock";
const expected = process.env.BPIR_EXPECT_ADMIN_PROBE;
const label = process.env.BPIR_ADMIN_PROBE_LABEL ?? "unspecified";
const format = process.env.BPIR_ADMIN_PROBE_FORMAT ?? "text";

if (!new Set(["EACCES", "root-readback"]).has(expected)) {
  throw new Error("BPIR_EXPECT_ADMIN_PROBE must equal EACCES or root-readback");
}
if (!new Set(["json", "text"]).has(format)) {
  throw new Error("BPIR_ADMIN_PROBE_FORMAT must equal json or text");
}

function effectiveCapabilities() {
  const match = /^CapEff:\s*([0-9a-f]+)$/imu.exec(readFileSync("/proc/self/status", "utf8"));
  if (match === null) throw new Error("admin probe could not read CapEff from /proc/self/status");
  return match[1].toLowerCase();
}

function writeResult({ bodySha256, error, listen, status, transport }) {
  if (format === "json") {
    process.stdout.write(`${JSON.stringify({
      body_sha256: bodySha256,
      cap_eff: effectiveCapabilities(),
      error,
      gid: process.getegid?.() ?? null,
      groups: process.getgroups?.().sort((left, right) => left - right) ?? null,
      label,
      listen,
      path: "/config/",
      status,
      transport,
      uid: process.geteuid?.() ?? null,
    })}\n`);
    return;
  }
  if (error === "EACCES") process.stdout.write(`admin-probe=${label} PASS error=EACCES\n`);
  else process.stdout.write("admin-probe=root-readback PASS status=200\n");
}

await new Promise((resolve, reject) => {
  const probe = request(
    {
      method: "GET",
      path: "/config/",
      socketPath,
      timeout: 3_000,
    },
    (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_ADAPTED_JSON_BYTES) {
          response.destroy(
            new Error(`admin readback exceeded ${MAX_ADAPTED_JSON_BYTES} bytes`),
          );
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (expected !== "root-readback") {
          reject(new Error(`${label} unexpectedly reached the admin API with status ${response.statusCode}`));
          return;
        }
        if (response.statusCode !== 200) {
          reject(new Error(`root admin readback returned status ${response.statusCode}`));
          return;
        }
        const body = Buffer.concat(chunks);
        let canonical;
        try {
          canonical = canonicalizeAdaptedCaddyJson(body, "root admin readback");
        } catch (error) {
          reject(new Error(`root admin readback was not approved canonical JSON: ${error.message}`));
          return;
        }
        writeResult({
          bodySha256: sha256(canonical),
          error: null,
          listen: "unix//run/bitcoinpir-caddy-admin/admin.sock|0200",
          status: 200,
          transport: "unix",
        });
        resolve();
      });
    },
  );
  probe.on("timeout", () => probe.destroy(new Error(`${label} admin probe timed out`)));
  probe.on("error", (error) => {
    if (expected === "EACCES" && error.code === "EACCES") {
      writeResult({
        bodySha256: null,
        error: "EACCES",
        listen: null,
        status: null,
        transport: "unix",
      });
      resolve();
      return;
    }
    reject(new Error(`${label} admin probe failed with ${error.code ?? error.message}; expected ${expected}`));
  });
  probe.end();
});
