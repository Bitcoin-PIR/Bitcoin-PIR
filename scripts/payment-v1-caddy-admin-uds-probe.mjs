#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";

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
        if (size > 1_048_576) {
          response.destroy(new Error("admin readback exceeded 1 MiB"));
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
        let config;
        try {
          config = JSON.parse(body.toString("utf8"));
        } catch (error) {
          reject(new Error(`root admin readback was not JSON: ${error.message}`));
          return;
        }
        if (config?.admin?.listen !== "unix//run/bitcoinpir-caddy-admin/admin.sock|0200") {
          reject(new Error("root admin readback did not bind the exact Unix endpoint"));
          return;
        }
        writeResult({
          bodySha256: createHash("sha256").update(body).digest("hex"),
          error: null,
          listen: config.admin.listen,
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
