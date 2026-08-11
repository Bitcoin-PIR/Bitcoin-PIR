import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
const tier3FinishScript = path.join(
  scriptsDir,
  "dracut/97bpir-tier3-init/unified-server-finish.sh",
);
const directOramSupervisor = path.join(
  scriptsDir,
  "dracut/97bpir-tier3-init/direct-oram-supervisor.sh",
);

function write(pathname, contents = "fixture\n") {
  mkdirSync(path.dirname(pathname), { recursive: true });
  writeFileSync(pathname, contents);
}

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
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
    .replace(
      "ORAM_SUPERVISOR=/usr/local/bin/direct-oram-supervisor",
      `ORAM_SUPERVISOR=${directOramSupervisor}`,
    )
    .replace("UNIFIED_SERVER=/usr/local/bin/unified_server", `UNIFIED_SERVER=${unifiedServer}`)
    .replace("TRUSTED_INPUT_ROOT=/run/bitcoinpir-oram-inputs", `TRUSTED_INPUT_ROOT=${mismatchRoot}/trusted-inputs`)
    .replace("TRUSTED_STATE_ROOT=/run/bitcoinpir-oram-state", `TRUSTED_STATE_ROOT=${mismatchRoot}/trusted-state`)
    .replaceAll("sleep 5", ":");
  writeFileSync(fixtureRunScript, transformed);
  chmodSync(fixtureRunScript, 0o755);
  const mismatch = run("sh", [fixtureRunScript]);
  assert.notEqual(mismatch.status, 0, mismatch.stdout + mismatch.stderr);
  assert.match(mismatch.stderr, /db0 runtime\/proof MANIFEST bytes differ/);
  assert.equal(existsSync(marker), false, "oramctl must not run after manifest mismatch");

  const directRoot = path.join(tempRoot, "direct-success");
  const directData = path.join(directRoot, "data");
  const directMarker = path.join(directRoot, "oramctl.calls");
  const unifiedArgs = path.join(directRoot, "unified-server.args");
  const directOramctl = path.join(directRoot, "oramctl");
  const directUnifiedServer = path.join(directRoot, "unified_server");
  const directBhtmProof = path.join(directRoot, "height-940611.leaf-proof.json");
  const db0Index = "db0-index-fixture\n";
  const db0Chunks = "db0-chunks-fixture\n";
  const db1Index = "db1-index-fixture\n";
  const db1Chunks = "db1-chunks-fixture\n";

  function writeDirectDb(dbName, manifest, indexContents, chunksContents) {
    const runtimeDir = path.join(directData, `${dbName}-runtime`);
    const proofDir = path.join(directData, `${dbName}-proof`);
    write(path.join(runtimeDir, "MANIFEST.toml"), manifest);
    write(path.join(proofDir, "server-db/MANIFEST.toml"), manifest);
    write(path.join(proofDir, "build-evidence.bin"));
    write(path.join(proofDir, "root-bundle-payload.bin"));
    write(
      path.join(proofDir, "oram-direct-inputs/utxo_chunks_index_nodust.bin"),
      indexContents,
    );
    write(
      path.join(proofDir, "oram-direct-inputs/utxo_chunks_nodust.bin"),
      chunksContents,
    );
    write(
      path.join(proofDir, "oram-direct-inputs/direct-inputs.sha256"),
      `${sha256(indexContents)}  utxo_chunks_index_nodust.bin\n${sha256(chunksContents)}  utxo_chunks_nodust.bin\n`,
    );
  }

  writeDirectDb("db0", "db0 runtime manifest\n", db0Index, db0Chunks);
  writeDirectDb("db1", "db1 runtime manifest\n", db1Index, db1Chunks);
  write(
    path.join(directData, "databases.toml"),
    `[[database]]\nname = "main"\ntype = "full"\npath = "db0-runtime"\nproof_dir = "db0-proof"\nbase_height = 0\nheight = 948454\n\n[[database]]\nname = "delta"\ntype = "delta"\npath = "db1-runtime"\nproof_dir = "db1-proof"\nbase_height = 940611\nheight = 948454\n`,
  );
  write(directBhtmProof, "{}\n");
  write(
    directOramctl,
    `#!/bin/sh
out=
state=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir) out=$2; shift 2 ;;
    --trusted-state-dir) state=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$out" ] && [ -n "$state" ] || exit 2
mkdir -p "$out" "$state"
for level in direct-index direct-chunk; do
  for suffix in meta.oram payload.oram meta.hash.oram payload.hash.oram; do
    printf fixture > "$out/$level.$suffix"
  done
  for suffix in state auth.state metadata; do
    printf fixture > "$state/$level.$suffix"
  done
done
printf '%s|%s\n' "$out" "$state" >> "${directMarker}"
`,
  );
  write(
    directUnifiedServer,
    `#!/bin/sh
printf '%s\n' "$@" > "${unifiedArgs}"
`,
  );
  chmodSync(directOramctl, 0o755);
  chmodSync(directUnifiedServer, 0o755);

  const directRunScript = path.join(directRoot, "unified-server-run.sh");
  const directTransformed = readFileSync(tier3RunScript, "utf8")
    .replaceAll("/home/pir/data", directData)
    .replace("/usr/share/bitcoinpir/proofs/height-940611.leaf-proof.json", directBhtmProof)
    .replace("ORAMCTL=/usr/local/bin/oramctl", `ORAMCTL=${directOramctl}`)
    .replace(
      "ORAM_SUPERVISOR=/usr/local/bin/direct-oram-supervisor",
      `ORAM_SUPERVISOR=${directOramSupervisor}`,
    )
    .replace(
      "UNIFIED_SERVER=/usr/local/bin/unified_server",
      `UNIFIED_SERVER=${directUnifiedServer}`,
    )
    .replace(
      "TRUSTED_INPUT_ROOT=/run/bitcoinpir-oram-inputs",
      `TRUSTED_INPUT_ROOT=${directRoot}/trusted-inputs`,
    )
    .replace(
      "TRUSTED_STATE_ROOT=/run/bitcoinpir-oram-state",
      `TRUSTED_STATE_ROOT=${directRoot}/trusted-state`,
    )
    .replace("ORAM_DB0_MAX_SECONDS=480", "ORAM_DB0_MAX_SECONDS=5")
    .replace("ORAM_DB1_MAX_SECONDS=180", "ORAM_DB1_MAX_SECONDS=5")
    .replace("ORAM_TOTAL_MAX_SECONDS=900", "ORAM_TOTAL_MAX_SECONDS=20")
    .replace("ORAM_HEARTBEAT_INTERVAL_SECONDS=15", "ORAM_HEARTBEAT_INTERVAL_SECONDS=1")
    .replace("ORAM_HEARTBEAT_DEADLINE_SECONDS=90", "ORAM_HEARTBEAT_DEADLINE_SECONDS=3")
    .replace("ORAM_KILL_GRACE_SECONDS=5", "ORAM_KILL_GRACE_SECONDS=0")
    .replace(
      /MAINNET_EXPECTED_INDEX_SHA256=[0-9a-f]{64}/,
      `MAINNET_EXPECTED_INDEX_SHA256=${sha256(db0Index)}`,
    )
    .replace(
      /MAINNET_EXPECTED_CHUNKS_SHA256=[0-9a-f]{64}/,
      `MAINNET_EXPECTED_CHUNKS_SHA256=${sha256(db0Chunks)}`,
    )
    .replace(
      /DELTA_EXPECTED_INDEX_SHA256=[0-9a-f]{64}/,
      `DELTA_EXPECTED_INDEX_SHA256=${sha256(db1Index)}`,
    )
    .replace(
      /DELTA_EXPECTED_CHUNKS_SHA256=[0-9a-f]{64}/,
      `DELTA_EXPECTED_CHUNKS_SHA256=${sha256(db1Chunks)}`,
    )
    .replaceAll("sleep 5", ":");
  writeFileSync(directRunScript, directTransformed);
  chmodSync(directRunScript, 0o755);
  const directSuccess = run("sh", [directRunScript]);
  assert.equal(directSuccess.status, 0, directSuccess.stdout + directSuccess.stderr);
  const directCalls = readFileSync(directMarker, "utf8");
  assert.match(directCalls, /db0-mainnet-948454/);
  assert.match(directCalls, /db1-delta-940611-948454/);
  const finalArgs = readFileSync(unifiedArgs, "utf8");
  assert.match(finalArgs, /--direct-oram-db\n0=.*db0-mainnet-948454/);
  assert.match(finalArgs, /--direct-oram-db\n1=.*db1-delta-940611-948454/);
  for (const label of ["mainnet-948454", "delta-940611-948454"]) {
    assert.match(
      readFileSync(path.join(directData, "oram-boot-logs", `${label}.status.env`), "utf8"),
      /status=success[\s\S]*reason=none/,
    );
  }

  const guardRoot = path.join(tempRoot, "runit-guard");
  const guardState = path.join(guardRoot, "state");
  const guardStatus = path.join(guardRoot, "status");
  const guardService = path.join(guardRoot, "service");
  const svLog = path.join(guardRoot, "sv.log");
  const fakeSv = path.join(guardRoot, "sv");
  write(fakeSv, `#!/bin/sh\nprintf '%s\\n' "$*" >> "${svLog}"\n`);
  chmodSync(fakeSv, 0o755);
  mkdirSync(guardService, { recursive: true });
  const guardEnv = {
    ...process.env,
    BPIR_RUNIT_GUARD_STATE_DIR: guardState,
    BPIR_RUNIT_GUARD_STATUS_DIR: guardStatus,
    BPIR_RUNIT_GUARD_SV_BIN: fakeSv,
    BPIR_RUNIT_GUARD_SERVICE_DIR: guardService,
  };
  for (let failure = 1; failure <= 3; failure += 1) {
    const result = run("sh", [tier3FinishScript, "134", "6"], { env: guardEnv });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(readFileSync(path.join(guardState, "failure_count"), "utf8"), `${failure}\n`);
    assert.equal(existsSync(svLog), failure === 3);
  }
  assert.equal(readFileSync(svLog, "utf8"), `-w 1 down ${guardService}\n`);
  assert.match(
    readFileSync(path.join(guardStatus, "unified-server-runit.status"), "utf8"),
    /status=restart_suppressed[\s\S]*failure_count=3[\s\S]*action=down/,
  );

  writeFileSync(path.join(guardState, "failure_count"), "2\n");
  writeFileSync(
    path.join(guardState, "last_failure_at"),
    `${Math.floor(Date.now() / 1000) - 601}\n`,
  );
  rmSync(svLog);
  const afterStableWindow = run("sh", [tier3FinishScript, "1", "0"], { env: guardEnv });
  assert.equal(afterStableWindow.status, 0, afterStableWindow.stdout + afterStableWindow.stderr);
  assert.equal(readFileSync(path.join(guardState, "failure_count"), "utf8"), "1\n");
  assert.equal(existsSync(svLog), false);

  const supervisorRoot = path.join(tempRoot, "direct-oram-supervisor");
  const supervisorStatus = path.join(supervisorRoot, "status");
  const successfulOutput = path.join(supervisorRoot, "successful-output");
  const successfulLog = path.join(supervisorRoot, "successful.log");
  const successfulWorker = path.join(supervisorRoot, "successful-worker.sh");
  write(
    successfulWorker,
    `#!/bin/sh\nprintf fixture > "$1/output.bin"\nsleep 2\n`,
  );
  chmodSync(successfulWorker, 0o755);
  const supervisedSuccess = run("sh", [
    directOramSupervisor,
    "fixture-db0",
    "5",
    "1",
    "3",
    "1",
    supervisorStatus,
    successfulOutput,
    successfulLog,
    "--",
    successfulWorker,
    successfulOutput,
  ]);
  assert.equal(supervisedSuccess.status, 0, supervisedSuccess.stdout + supervisedSuccess.stderr);
  assert.match(
    readFileSync(path.join(supervisorStatus, "fixture-db0.status.env"), "utf8"),
    /status=success[\s\S]*reason=none[\s\S]*timeout_seconds=5/,
  );
  assert.match(
    readFileSync(path.join(supervisorStatus, "fixture-db0.heartbeat.env"), "utf8"),
    /status=running[\s\S]*database=fixture-db0[\s\S]*output_kib=[1-9][0-9]*/,
  );

  const timeoutOutput = path.join(supervisorRoot, "timeout-output");
  const timeoutLog = path.join(supervisorRoot, "timeout.log");
  const timeoutWorker = path.join(supervisorRoot, "timeout-worker.sh");
  write(timeoutWorker, "#!/bin/sh\nsleep 5\nprintf late > \"$1/late\"\n");
  chmodSync(timeoutWorker, 0o755);
  const supervisedTimeout = run("sh", [
    directOramSupervisor,
    "fixture-db1-timeout",
    "1",
    "1",
    "3",
    "0",
    supervisorStatus,
    timeoutOutput,
    timeoutLog,
    "--",
    timeoutWorker,
    timeoutOutput,
  ]);
  assert.equal(supervisedTimeout.status, 124, supervisedTimeout.stdout + supervisedTimeout.stderr);
  assert.match(
    readFileSync(path.join(supervisorStatus, "fixture-db1-timeout.status.env"), "utf8"),
    /status=timed_out[\s\S]*reason=build-timeout/,
  );
  assert.equal(existsSync(path.join(timeoutOutput, "late")), false);

  execFileSync("sh", ["-n", stageHelper]);
  execFileSync("sh", ["-n", tier3RunScript]);
  execFileSync("sh", ["-n", tier3FinishScript]);
  execFileSync("sh", ["-n", directOramSupervisor]);
  console.log("vpsbg Tier3 generation fixtures: ok");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
