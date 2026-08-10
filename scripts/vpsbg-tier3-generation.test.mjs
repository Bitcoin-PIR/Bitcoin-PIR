import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const stageHelper = path.join(scriptsDir, "stage_vpsbg_tier3_generation.sh");
const tier3RunScript = path.join(
  scriptsDir,
  "dracut/97bpir-tier3-init/unified-server-run.sh",
);

function write(pathname, contents = "fixture\n") {
  mkdirSync(path.dirname(pathname), { recursive: true });
  writeFileSync(pathname, contents);
}

function createCompleteOutput(root, name, manifest) {
  const output = path.join(root, name);
  for (const relative of [
    "server-db/MANIFEST.toml",
    "build-evidence.bin",
    "root-bundle-payload.bin",
    "build-evidence.sev-snp-report.bin",
    "database.manifest.sha256",
    "all-artifacts.manifest.sha256",
    "oram-direct-inputs/utxo_chunks_index_nodust.bin",
    "oram-direct-inputs/utxo_chunks_nodust.bin",
    "oram-direct-inputs/direct-inputs.sha256",
  ]) {
    write(path.join(output, relative), relative.includes("MANIFEST") ? manifest : "fixture\n");
  }
  return output;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.error) throw result.error;
  return result;
}

const tempRoot = mkdtempSync(path.join(os.tmpdir(), "bpir-tier3-generation-"));
try {
  const dataRoot = path.join(tempRoot, "data");
  mkdirSync(dataRoot, { recursive: true });
  const activeCatalog = path.join(dataRoot, "databases.toml");
  writeFileSync(activeCatalog, "# known-active catalog\n");

  const db0 = createCompleteOutput(tempRoot, "db0-output", "db0 manifest\n");
  const db1 = createCompleteOutput(tempRoot, "db1-output", "db1 manifest\n");
  const stage = run("bash", [
    stageHelper,
    "--generation",
    "fixture-1",
    "--db0-output",
    db0,
    "--db1-output",
    db1,
    "--db0-name",
    "main",
    "--db0-type",
    "full",
    "--db0-base-height",
    "0",
    "--db0-height",
    "948454",
    "--db1-name",
    "delta_940611_948454",
    "--db1-type",
    "delta",
    "--db1-base-height",
    "940611",
    "--db1-height",
    "948454",
    "--data-root",
    dataRoot,
  ]);
  assert.equal(stage.status, 0, stage.stdout + stage.stderr);
  assert.equal(readFileSync(activeCatalog, "utf8"), "# known-active catalog\n");
  const candidate = path.join(dataRoot, "databases.toml.candidate-fixture-1");
  assert.ok(existsSync(candidate));
  const candidateText = readFileSync(candidate, "utf8");
  assert.ok(candidateText.includes(`path = "${dataRoot}/generations/fixture-1/db0/server-db"`));
  assert.ok(candidateText.includes(`proof_dir = "${dataRoot}/generations/fixture-1/db1"`));
  assert.equal(
    readFileSync(path.join(dataRoot, "generations/fixture-1/db0/server-db/MANIFEST.toml"), "utf8"),
    "db0 manifest\n",
  );

  const mismatchRoot = path.join(tempRoot, "mismatch");
  const mismatchData = path.join(mismatchRoot, "data");
  const marker = path.join(mismatchRoot, "oramctl-invoked");
  const oramctl = path.join(mismatchRoot, "oramctl");
  const unifiedServer = path.join(mismatchRoot, "unified_server");
  const bhtmProof = path.join(mismatchRoot, "height-940611.leaf-proof.json");
  write(oramctl, `#!/bin/sh\nprintf invoked > "${marker}"\n`);
  write(unifiedServer, "#!/bin/sh\nexit 0\n");
  chmodSync(oramctl, 0o755);
  chmodSync(unifiedServer, 0o755);
  write(bhtmProof, "{}\n");
  write(path.join(mismatchData, "runtime-db0/MANIFEST.toml"), "runtime manifest\n");
  write(path.join(mismatchData, "proof-db0/server-db/MANIFEST.toml"), "proof manifest\n");
  write(
    path.join(mismatchData, "databases.toml"),
    `[[database]]\nname = "main"\ntype = "full"\npath = "runtime-db0"\nproof_dir = "proof-db0"\nbase_height = 0\nheight = 948454\n\n[[database]]\nname = "delta"\ntype = "delta"\npath = "runtime-db1"\nproof_dir = "proof-db1"\nbase_height = 940611\nheight = 948454\n`,
  );

  const fixtureRunScript = path.join(mismatchRoot, "unified-server-run.sh");
  const transformed = readFileSync(tier3RunScript, "utf8")
    .replaceAll("/home/pir/data", mismatchData)
    .replace("/usr/share/bitcoinpir/proofs/height-940611.leaf-proof.json", bhtmProof)
    .replace("ORAMCTL=/usr/local/bin/oramctl", `ORAMCTL=${oramctl}`)
    .replace("UNIFIED_SERVER=/usr/local/bin/unified_server", `UNIFIED_SERVER=${unifiedServer}`)
    .replace("TRUSTED_INPUT_ROOT=/run/bitcoinpir-oram-inputs", `TRUSTED_INPUT_ROOT=${mismatchRoot}/trusted-inputs`)
    .replace("TRUSTED_STATE_ROOT=/run/bitcoinpir-oram-state", `TRUSTED_STATE_ROOT=${mismatchRoot}/trusted-state`)
    .replace("VPSBG_DPF_ONLY_FUNCTIONAL_BETA=1", "VPSBG_DPF_ONLY_FUNCTIONAL_BETA=0")
    .replaceAll("sleep 5", ":");
  writeFileSync(fixtureRunScript, transformed);
  chmodSync(fixtureRunScript, 0o755);
  const mismatch = run("sh", [fixtureRunScript]);
  assert.notEqual(mismatch.status, 0, mismatch.stdout + mismatch.stderr);
  assert.match(mismatch.stderr, /db0 runtime\/proof MANIFEST bytes differ/);
  assert.equal(existsSync(marker), false, "oramctl must not run after manifest mismatch");

  execFileSync("sh", ["-n", stageHelper]);
  execFileSync("sh", ["-n", tier3RunScript]);
  console.log("vpsbg Tier3 generation fixtures: ok");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
