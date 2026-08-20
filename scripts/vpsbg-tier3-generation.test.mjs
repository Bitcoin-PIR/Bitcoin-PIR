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
  statSync,
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
const tier3ModuleSetup = path.join(
  scriptsDir,
  "dracut/97bpir-tier3-init/module-setup.sh",
);
const tier3FinishScript = path.join(
  scriptsDir,
  "dracut/97bpir-tier3-init/unified-server-finish.sh",
);
const tier3CloudflaredScript = path.join(
  scriptsDir,
  "dracut/97bpir-tier3-init/cloudflared-run.sh",
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

function createProofV1(root, name, manifest = "v1 manifest\n") {
  const proof = path.join(root, name);
  for (const relative of [
    "server-db/MANIFEST.toml",
    "build-evidence.bin",
    "root-bundle-payload.bin",
    "build-evidence.sev-snp-report.bin",
    "database.manifest.sha256",
    "all-artifacts.manifest.sha256",
  ]) {
    write(path.join(proof, relative), relative.includes("MANIFEST") ? manifest : "v1 fixture\n");
  }
  return proof;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.error) throw result.error;
  return result;
}

function writeSealedStartup(
  root,
  phase,
  ordinal = 1,
  servicePolicyPath = path.join(root, "service-policy.bin"),
) {
  const currentClassPath = path.join(root, `public/classes/${"43".repeat(32)}.bin`);
  const accountingAuthorizationPath = path.join(root, "provider-accounting-authorization.bin");
  const accountingApprovalPath = path.join(root, "issuer-accounting-approval.bin");
  if (!existsSync(servicePolicyPath)) write(servicePolicyPath, "fixture current policy\n");
  write(currentClassPath, "fixture current class\n");
  write(accountingAuthorizationPath, "provider-accounting-authorization.bin fixture\n");
  write(accountingApprovalPath, "issuer-accounting-approval.bin fixture\n");
  const artifactSet = `schema=bitcoinpir-pir2-bat-v2-public-artifact-set-v1
current_policy=${"42".repeat(32)}=${sha256(readFileSync(servicePolicyPath))}=${servicePolicyPath}
current_class=${"43".repeat(32)}=${sha256(readFileSync(currentClassPath))}=${currentClassPath}
accounting_authorization=${"49".repeat(32)}=${sha256(readFileSync(accountingAuthorizationPath))}=${accountingAuthorizationPath}
accounting_approval=${"4a".repeat(32)}=${sha256(readFileSync(accountingApprovalPath))}=${accountingApprovalPath}
`;
  const artifactSetPath = path.join(root, "public-artifact-set.env");
  write(artifactSetPath, artifactSet);
  write(
    path.join(root, "startup.env"),
    `schema=bitcoinpir-pir2-sealed-startup-v2
profile=pir2-snp-sealed-v1
phase=${phase}
ordinal=${ordinal}
verifier_nonce_hex=${"41".repeat(32)}
current_policy_digest_hex=${"42".repeat(32)}
class_digest_hex=${"43".repeat(32)}
artifact_set_path=${artifactSetPath}
artifact_set_sha256=${sha256(artifactSet)}
minimum_authorization_epoch=7
`,
  );
}

function authoritativeAttemptToken({
  kind,
  phase,
  bootIdHex,
  ordinal = 1,
  nonce = "41".repeat(32),
  policy = "42".repeat(32),
  classDigest = "43".repeat(32),
  artifactSetSha256 = "49".repeat(32),
  minimumAuthorizationEpoch = 7,
  receiptProtocolDigest = "44".repeat(32),
  receiptFileSha256 = "45".repeat(32),
}) {
  return `schema=bitcoinpir-pir2-sealed-authoritative-attempt-v2
kind=${kind}
phase=${phase}
boot_id=${bootIdHex}
ordinal=${ordinal}
verifier_nonce_hex=${nonce}
current_policy_digest_hex=${policy}
class_digest_hex=${classDigest}
artifact_set_sha256=${artifactSetSha256}
minimum_authorization_epoch=${minimumAuthorizationEpoch}
receipt_protocol_digest=${receiptProtocolDigest}
receipt_file_sha256=${receiptFileSha256}
`;
}

const tempRoot = mkdtempSync(path.join(os.tmpdir(), "bpir-tier3-generation-"));
try {
  const tier3RunText = readFileSync(tier3RunScript, "utf8");
  const tier3ModuleSetupText = readFileSync(tier3ModuleSetup, "utf8");
  assert.doesNotMatch(
    tier3RunText,
    /target\/release\/(?:unified_server|oramctl)/,
    "measured startup must not fall back to mutable-rootfs binaries",
  );
  assert.doesNotMatch(
    tier3RunText,
    /(?:server\.key|--identity-key-path|--service-shared-clearing-key|--service-storeless-bat-v2-pir1-clearing-key)/,
    "sealed pir2 startup must not accept a plaintext signing-key path",
  );
  assert.match(tier3RunText, /ulimit -c 0/);
  assert.match(tier3RunText, /active swap is forbidden for pir2 sealed startup/);
  assert.match(
    tier3RunText,
    /case "\$PIR2_SEALED_PHASE" in[\s\S]*observe\|enroll\|probe\)[\s\S]*run_pir2_sealed_inert_phase[\s\S]*wait_for_databases_config/,
    "inert sealed dispatch must precede the database wait",
  );
  assert.match(
    tier3RunText,
    /if \[ "\$PIR2_SEALED_PHASE" = observe \]; then[\s\S]*--pir2-snp-sealed-phase "\$PIR2_SEALED_PHASE"[\s\S]*else[\s\S]*require_file "\$PIR2_SEALED_RELEASE_PATH"[\s\S]*--pir2-snp-sealed-release "\$PIR2_SEALED_RELEASE_PATH"/,
    "Observe must run without a release while Enroll and Probe require one",
  );
  assert.match(
    tier3RunText,
    /ready\)[\s\S]*run_pir2_sealed_ready_preflight[\s\S]*esac[\s\S]*wait_for_databases_config[\s\S]*build_direct_oram mainnet[\s\S]*exec "\$UNIFIED_SERVER"[\s\S]*--pir2-snp-sealed-require-ready/,
    "Ready must preflight before databases/ORAM and reopen only in the final exec",
  );
  assert.match(tier3RunText, /ready-preflight-\$PIR2_BOOT_ID_HEX\.bin/);
  assert.match(tier3RunText, /ready-runtime-\$PIR2_BOOT_ID_HEX\.bin/);
  assert.match(
    tier3RunText,
    /validate_pir2_public_artifact_set[\s\S]*run_pir2_with_public_artifacts exec[\s\S]*--pir2-snp-sealed-require-ready/,
    "final serving must use sealed Ready plus the validated public BAT V2 artifact set",
  );
  assert.match(
    tier3RunText,
    /run_pir2_with_public_artifacts\(\)[\s\S]*--service-storeless-bat-v2-policy-digest-hex[\s\S]*--service-storeless-bat-v2-retained-policy[\s\S]*--service-storeless-bat-v2-class/,
    "the bounded artifact runner must project current, retained, and class flags",
  );
  assert.doesNotMatch(
    tier3ModuleSetupText,
    /(?:BPIR_TIER3_IDENTITY_KEY|server\.key)/,
    "Tier3 module must never embed the old identity seed",
  );
  assert.match(
    tier3ModuleSetupText,
    /busybox --list \| grep -qx httpd/,
    "Tier3 initramfs must refuse a BusyBox build without the httpd applet",
  );
  assert.match(
    tier3RunText,
    /"\$ORAM_STATUS_HTTPD" httpd -f/,
    "status API must use BusyBox httpd",
  );
  assert.match(tier3RunText, /status\.json/, "status API root must contain status.json");
  assert.match(
    tier3RunText,
    /start_direct_oram_status_api\nstart_total_watchdog[\s\S]*build_direct_oram mainnet/,
    "status API must start before Direct ORAM builds",
  );
  assert.match(
    tier3RunText,
    /stop_direct_oram_status_api[\s\S]*remove_direct_oram_status_api_root[\s\S]*exec "\$UNIFIED_SERVER"/,
    "status API must stop and remove its root before unified_server exec",
  );
  assert.doesNotMatch(
    tier3RunText.match(/write_direct_oram_status_json\(\)[\s\S]*?^}/m)?.[0] ?? "",
    /ORAM_PAGE_KEY_HEX/,
    "status JSON must not contain the ORAM page key",
  );
  const tier3CloudflaredText = readFileSync(tier3CloudflaredScript, "utf8");
  for (const [label, script] of [
    ["unified_server watchdog", tier3RunText],
    ["cloudflared readiness gate", tier3CloudflaredText],
  ]) {
    assert.doesNotMatch(script, /\bnc\s+-z\b/, `${label} must work with busybox nc`);
    assert.match(
      script,
      /\bnc\s+-w\s+1\s+[^\n]+<\/dev\/null\s+>\/dev\/null\s+2>&1/,
      `${label} must use the EOF-only portable TCP readiness probe`,
    );
  }

  const dataRoot = path.join(tempRoot, "data");
  mkdirSync(dataRoot, { recursive: true });
  const activeCatalog = path.join(dataRoot, "databases.toml");
  writeFileSync(activeCatalog, "# known-active catalog\n");

  const db0 = createCompleteOutput(tempRoot, "db0-output", "db0 manifest\n");
  const db1 = createCompleteOutput(tempRoot, "db1-output", "db1 manifest\n");
  const db0ProofV1 = createProofV1(tempRoot, "db0-proof-v1", "db0 v1 manifest\n");
  const db1ProofV1 = createProofV1(tempRoot, "db1-proof-v1", "db1 v1 manifest\n");
  const stage = run("bash", [
    stageHelper,
    "--generation",
    "fixture-1",
    "--db0-output",
    db0,
    "--db1-output",
    db1,
    "--db0-proof-v1",
    db0ProofV1,
    "--db1-proof-v1",
    db1ProofV1,
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
  assert.ok(candidateText.includes(`proof_dir = "${dataRoot}/generations/fixture-1/proof-v1/db1"`));
  assert.ok(candidateText.includes(`proof_v2_dir = "${dataRoot}/generations/fixture-1/db1"`));
  assert.equal(
    readFileSync(path.join(dataRoot, "generations/fixture-1/db0/server-db/MANIFEST.toml"), "utf8"),
    "db0 manifest\n",
  );
  assert.equal(
    readFileSync(
      path.join(dataRoot, "generations/fixture-1/proof-v1/db1/root-bundle-payload.bin"),
      "utf8",
    ),
    "v1 fixture\n",
  );

  const inertRoot = path.join(tempRoot, "sealed-inert");
  const inertBinary = path.join(inertRoot, "unified_server");
  const inertBootId = path.join(inertRoot, "boot_id");
  const inertSwaps = path.join(inertRoot, "swaps");
  const inertCalls = path.join(inertRoot, "unified-server.calls");
  const inertBusybox = path.join(inertRoot, "busybox");
  write(
    inertBusybox,
    `#!/bin/sh
[ "$1" = httpd ] || exit 2
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    -f) shift ;;
    -p) address=$2; shift 2 ;;
    -h) root=$2; shift 2 ;;
    *) exit 2 ;;
  esac
done
host=\${address%:*}
port=\${address##*:}
exec python3 -m http.server "$port" --bind "$host" --directory "$root"
`,
  );
  chmodSync(inertBusybox, 0o755);
  write(inertSwaps, "Filename\tType\tSize\tUsed\tPriority\n");
  write(
    inertBinary,
    `#!/bin/sh
phase=
receipt=
marker=
boot_id=
release_seen=absent
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pir2-snp-sealed-phase) phase=$2; shift 2 ;;
    --pir2-snp-sealed-receipt) receipt=$2; shift 2 ;;
    --pir2-snp-sealed-marker) marker=$2; shift 2 ;;
    --pir2-snp-sealed-current-boot-id-hex) boot_id=$2; shift 2 ;;
    --pir2-snp-sealed-release) release_seen=present; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s:%s\n' "$phase" "$release_seen" >> "${inertCalls}"
[ ! -e "$receipt" ] || exit 2
[ ! -e "$marker" ] || exit 2
printf 'fixture receipt\n' > "$receipt"
if [ "\${BPIR_TEST_PARTIAL_MARKER:-false}" = true ]; then
  printf 'schema=bitcoinpir-pir2-sealed-inert-success-v1\nphase=%s\n' "$phase" > "$marker"
  exit 42
fi
{
  printf 'schema=bitcoinpir-pir2-sealed-inert-success-v1\n'
  printf 'phase=%s\n' "$phase"
  printf 'boot_id=%s\n' "$boot_id"
  printf 'receipt_digest=%s\n' '${"44".repeat(32)}'
  printf 'exit_code=42\n'
} > "$marker"
exit 42
`,
  );
  chmodSync(inertBinary, 0o755);
  const inertRunScript = path.join(inertRoot, "unified-server-run.sh");
  writeFileSync(
    inertRunScript,
    tier3RunText
      .replace("UNIFIED_SERVER=/usr/local/bin/unified_server", `UNIFIED_SERVER=${inertBinary}`)
      .replace("PIR2_SEALED_RECEIPT_RECOVERY_HTTPD=/usr/bin/busybox", `PIR2_SEALED_RECEIPT_RECOVERY_HTTPD=${inertBusybox}`)
      .replaceAll("/run/bitcoinpir-pir2-sealed-receipt-api", `${inertRoot}/receipt-recovery-api`)
      .replaceAll("sleep 5", ":"),
  );
  chmodSync(inertRunScript, 0o755);
  for (const [index, phase] of ["observe", "enroll", "probe"].entries()) {
    const phaseRoot = path.join(inertRoot, phase);
    writeSealedStartup(phaseRoot, phase, index + 1);
    if (phase !== "observe") {
      write(path.join(phaseRoot, "release.bin"), "fixture signed release\n");
    }
    const bootId = `${index + 1}`.repeat(8);
    writeFileSync(
      inertBootId,
      `${bootId}-${bootId.slice(0, 4)}-${bootId.slice(0, 4)}-${bootId.slice(0, 4)}-${bootId}${bootId.slice(0, 4)}\n`,
    );
    const inertEnv = {
      ...process.env,
      BPIR_ORAM_BOOT_ID_FILE: inertBootId,
      BPIR_PIR2_PROC_SWAPS: inertSwaps,
      BPIR_PIR2_SNP_SEALED_ROOT: phaseRoot,
      BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: path.join(phaseRoot, "trusted-attempt"),
      BPIR_TEST_PIR2_SEALED_RECEIPT_RECOVERY_WINDOW_SECONDS: "1",
    };
    const inert = run("sh", [inertRunScript], { env: inertEnv });
    assert.equal(inert.status, 42, inert.stdout + inert.stderr);
    assert.equal(
      readFileSync(inertCalls, "utf8").trim().split("\n").at(-1),
      `${phase}:${phase === "observe" ? "absent" : "present"}`,
    );
    assert.equal(existsSync(path.join(phaseRoot, "databases.toml")), false);
    const callsBeforeRetry = readFileSync(inertCalls, "utf8");
    const retry = run("sh", [inertRunScript], { env: inertEnv });
    assert.equal(retry.status, 42, retry.stdout + retry.stderr);
    assert.equal(readFileSync(inertCalls, "utf8"), callsBeforeRetry);
    assert.match(retry.stderr, /terminal attempt already completed/);

    const startupPath = path.join(phaseRoot, "startup.env");
    const originalStartup = readFileSync(startupPath, "utf8");
    writeSealedStartup(phaseRoot, phase, index + 101);
    const crossAttempt = run("sh", [inertRunScript], { env: inertEnv });
    assert.notEqual(crossAttempt.status, 42, crossAttempt.stdout + crossAttempt.stderr);
    assert.match(crossAttempt.stderr, /token does not match the current attempt/);
    assert.equal(readFileSync(inertCalls, "utf8"), callsBeforeRetry);
    writeFileSync(startupPath, originalStartup);
  }

  // Exercise the bounded endpoint through the same BusyBox-httpd invocation
  // shape as the UKI: the canonical receipt and minimal status are readable
  // during the one-second fixture window, then the inert attempt stays 42.
  const recoveryRoot = path.join(inertRoot, "recovery-window");
  writeSealedStartup(recoveryRoot, "observe", 77);
  writeFileSync(inertBootId, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n");
  const recoveryApiRoot = path.join(inertRoot, "receipt-recovery-api");
  const recoveryReceiptOutput = path.join(inertRoot, "recovered-receipt.bin");
  const recoveryStatusOutput = path.join(inertRoot, "recovered-status.json");
  const recoveryRunner = `
"$1" >"$2" 2>"$3" &
pid=$!
i=0
while [ ! -f "$4/status.json" ]; do
  [ "$i" -lt 100 ] || exit 3
  sleep 0.02
  i=$((i + 1))
done
j=0
until curl -fsS "http://127.0.0.1:8091/pir2-sealed-receipt.bin" >"$5"; do
  [ "$j" -lt 50 ] || exit 4
  sleep 0.02
  j=$((j + 1))
done
curl -fsS "http://127.0.0.1:8091/status.json" >"$6" || exit 5
wait "$pid"
exit $?
`;
  const recovery = run(
    "sh",
    [
      "-c",
      recoveryRunner,
      "fixture",
      inertRunScript,
      path.join(inertRoot, "recovery.stdout"),
      path.join(inertRoot, "recovery.stderr"),
      recoveryApiRoot,
      recoveryReceiptOutput,
      recoveryStatusOutput,
    ],
    {
      env: {
        ...process.env,
        BPIR_ORAM_BOOT_ID_FILE: inertBootId,
        BPIR_PIR2_PROC_SWAPS: inertSwaps,
        BPIR_PIR2_SNP_SEALED_ROOT: recoveryRoot,
        BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: path.join(recoveryRoot, "trusted-attempt"),
        BPIR_TEST_PIR2_SEALED_RECEIPT_RECOVERY_WINDOW_SECONDS: "1",
      },
    },
  );
  assert.equal(recovery.status, 42, recovery.stdout + recovery.stderr);
  assert.equal(readFileSync(recoveryReceiptOutput, "utf8"), "fixture receipt\n");
  assert.match(
    readFileSync(recoveryStatusOutput, "utf8"),
    /"phase":"observe","ordinal":77,"boot_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","receipt_sha256":"[0-9a-f]{64}"/,
  );
  assert.equal(existsSync(recoveryApiRoot), false, "receipt recovery root must be removed after its bounded window");

  const forgedRoot = path.join(inertRoot, "forged-persistent");
  const forgedAttemptRoot = path.join(forgedRoot, "trusted-attempt");
  writeSealedStartup(forgedRoot, "observe", 9);
  writeFileSync(inertBootId, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n");
  write(path.join(forgedRoot, "receipts/inert-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin"), "not a canonical receipt\n");
  write(
    path.join(forgedRoot, "markers/inert-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.env"),
    `schema=bitcoinpir-pir2-sealed-inert-success-v1
phase=observe
boot_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
receipt_digest=${"aa".repeat(32)}
exit_code=42
`,
  );
  const callsBeforeForgedPair = readFileSync(inertCalls, "utf8");
  const forgedPair = run("sh", [inertRunScript], {
    env: {
      ...process.env,
      BPIR_ORAM_BOOT_ID_FILE: inertBootId,
      BPIR_PIR2_PROC_SWAPS: inertSwaps,
      BPIR_PIR2_SNP_SEALED_ROOT: forgedRoot,
      BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: forgedAttemptRoot,
    },
  });
  assert.notEqual(forgedPair.status, 42, forgedPair.stdout + forgedPair.stderr);
  assert.match(forgedPair.stderr, /dispatcher failed with exit 2/);
  assert.equal(existsSync(path.join(forgedAttemptRoot, "terminal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.env")), false);
  assert.notEqual(readFileSync(inertCalls, "utf8"), callsBeforeForgedPair, "persistent audit files must not skip the measured child");

  const partialRoot = path.join(inertRoot, "partial-marker");
  const partialAttemptRoot = path.join(partialRoot, "trusted-attempt");
  writeSealedStartup(partialRoot, "probe", 10);
  write(path.join(partialRoot, "release.bin"), "fixture signed release\n");
  const callsBeforePartialMarker = readFileSync(inertCalls, "utf8");
  const partialMarker = run("sh", [inertRunScript], {
    env: {
      ...process.env,
      BPIR_ORAM_BOOT_ID_FILE: inertBootId,
      BPIR_PIR2_PROC_SWAPS: inertSwaps,
      BPIR_PIR2_SNP_SEALED_ROOT: partialRoot,
      BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: partialAttemptRoot,
      BPIR_TEST_PARTIAL_MARKER: "true",
    },
  });
  assert.notEqual(partialMarker.status, 42, partialMarker.stdout + partialMarker.stderr);
  assert.match(partialMarker.stderr, /audit marker has unexpected fields/);
  assert.notEqual(
    readFileSync(inertCalls, "utf8"),
    callsBeforePartialMarker,
    "the measured child must actually run before the truncated marker is rejected",
  );
  assert.equal(existsSync(path.join(partialAttemptRoot, "terminal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.env")), false);

  const partialTokenRoot = path.join(inertRoot, "partial-token");
  const partialTokenAttemptRoot = path.join(partialTokenRoot, "trusted-attempt");
  writeSealedStartup(partialTokenRoot, "enroll", 11);
  write(path.join(partialTokenRoot, "release.bin"), "fixture signed release\n");
  write(
    path.join(partialTokenAttemptRoot, "terminal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.env"),
    "schema=bitcoinpir-pir2-sealed-authoritative-attempt-v1\nkind=terminal\n",
  );
  const callsBeforePartialToken = readFileSync(inertCalls, "utf8");
  const partialToken = run("sh", [inertRunScript], {
    env: {
      ...process.env,
      BPIR_ORAM_BOOT_ID_FILE: inertBootId,
      BPIR_PIR2_PROC_SWAPS: inertSwaps,
      BPIR_PIR2_SNP_SEALED_ROOT: partialTokenRoot,
      BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: partialTokenAttemptRoot,
    },
  });
  assert.notEqual(partialToken.status, 42, partialToken.stdout + partialToken.stderr);
  assert.match(partialToken.stderr, /token has unexpected fields/);
  assert.equal(readFileSync(inertCalls, "utf8"), callsBeforePartialToken);

  const mismatchRoot = path.join(tempRoot, "mismatch");
  const mismatchData = path.join(mismatchRoot, "data");
  const marker = path.join(mismatchRoot, "oramctl-invoked");
  const oramctl = path.join(mismatchRoot, "oramctl");
  const unifiedServer = path.join(mismatchRoot, "unified_server");
  const bhtmProof = path.join(mismatchRoot, "height-940611.leaf-proof.json");
  const mismatchBootId = path.join(mismatchRoot, "boot_id");
  const mismatchSwaps = path.join(mismatchRoot, "swaps");
  const mismatchServicePolicy = path.join(mismatchRoot, "service-policy.bin");
  write(oramctl, `#!/bin/sh\nprintf invoked > "${marker}"\n`);
  write(
    unifiedServer,
    `#!/bin/sh
preflight=false
receipt=
marker=
boot_id=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pir2-snp-sealed-preflight-only) preflight=true; shift ;;
    --pir2-snp-sealed-receipt) receipt=$2; shift 2 ;;
    --pir2-snp-sealed-marker) marker=$2; shift 2 ;;
    --pir2-snp-sealed-current-boot-id-hex) boot_id=$2; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$preflight" = true ]; then
  printf 'fixture receipt\n' > "$receipt"
  {
    printf 'schema=bitcoinpir-pir2-sealed-inert-success-v1\n'
    printf 'phase=ready\n'
    printf 'boot_id=%s\n' "$boot_id"
    printf 'receipt_digest=%s\n' '${"46".repeat(32)}'
    printf 'exit_code=42\n'
  } > "$marker"
  exit 42
fi
exit 0
`,
  );
  chmodSync(oramctl, 0o755);
  chmodSync(unifiedServer, 0o755);
  write(bhtmProof, "{}\n");
  write(mismatchSwaps, "Filename\tType\tSize\tUsed\tPriority\n");
  write(mismatchServicePolicy, "fixture policy\n");
  writeFileSync(mismatchBootId, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n");
  write(path.join(mismatchData, "runtime-db0/MANIFEST.toml"), "runtime manifest\n");
  createProofV1(mismatchData, "proof-v1-db0");
  createProofV1(mismatchData, "proof-v1-db1");
  write(path.join(mismatchData, "proof-v2-db0/server-db/MANIFEST.toml"), "proof manifest\n");
  writeSealedStartup(path.join(mismatchData, "pir2-sealed"), "ready", 1, mismatchServicePolicy);
  write(
    path.join(mismatchData, "databases.toml"),
    `[[database]]\nname = "main"\ntype = "full"\npath = "runtime-db0"\nproof_dir = "proof-v1-db0"\nproof_v2_dir = "proof-v2-db0"\nbase_height = 0\nheight = 948454\n\n[[database]]\nname = "delta"\ntype = "delta"\npath = "runtime-db1"\nproof_dir = "proof-v1-db1"\nproof_v2_dir = "proof-v2-db1"\nbase_height = 940611\nheight = 948454\n`,
  );

  const fixtureRunScript = path.join(mismatchRoot, "unified-server-run.sh");
  const transformed = readFileSync(tier3RunScript, "utf8")
    .replaceAll("/home/pir/data", mismatchData)
    .replace("SERVICE_POLICY_PATH=/etc/bitcoinpir/payment/service-policy.bin", `SERVICE_POLICY_PATH=${mismatchServicePolicy}`)
    .replace("/usr/share/bitcoinpir/proofs/height-940611.leaf-proof.json", bhtmProof)
    .replace("ORAMCTL=/usr/local/bin/oramctl", `ORAMCTL=${oramctl}`)
    .replace(
      "ORAM_SUPERVISOR=/usr/local/bin/direct-oram-supervisor",
      `ORAM_SUPERVISOR=${directOramSupervisor}`,
    )
    .replace("UNIFIED_SERVER=/usr/local/bin/unified_server", `UNIFIED_SERVER=${unifiedServer}`)
    .replace("TRUSTED_INPUT_ROOT=/run/bitcoinpir-oram-inputs", `TRUSTED_INPUT_ROOT=${mismatchRoot}/trusted-inputs`)
    .replace("TRUSTED_STATE_ROOT=/run/bitcoinpir-oram-state", `TRUSTED_STATE_ROOT=${mismatchRoot}/trusted-state`)
    .replaceAll("/run/bitcoinpir-oram-status-api", `${mismatchRoot}/status-api`)
    .replaceAll("sleep 5", ":");
  writeFileSync(fixtureRunScript, transformed);
  chmodSync(fixtureRunScript, 0o755);
  const mismatch = run("sh", [fixtureRunScript], {
    env: {
      ...process.env,
      BPIR_ORAM_BOOT_ID_FILE: mismatchBootId,
      BPIR_PIR2_PROC_SWAPS: mismatchSwaps,
      BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: path.join(mismatchRoot, "trusted-attempt"),
      PATH: process.env.PATH,
    },
  });
  assert.notEqual(mismatch.status, 0, mismatch.stdout + mismatch.stderr);
  assert.match(mismatch.stderr, /db0 runtime\/proof-v2 MANIFEST bytes differ/);
  assert.equal(existsSync(marker), false, "oramctl must not run after manifest mismatch");

  const directRoot = path.join(tempRoot, "direct-success");
  const directData = path.join(directRoot, "data");
  const directMarker = path.join(directRoot, "oramctl.calls");
  const directEvents = path.join(directRoot, "startup.events");
  const unifiedArgs = path.join(directRoot, "unified-server.args");
  const unifiedStarts = path.join(directRoot, "unified-server.starts");
  const readySignal = path.join(directRoot, "unified-server.ready");
  const bootIdFile = path.join(directRoot, "boot_id");
  const fixtureBin = path.join(directRoot, "bin");
  const directOramctl = path.join(directRoot, "oramctl");
  const directUnifiedServer = path.join(directRoot, "unified_server");
  const directBhtmProof = path.join(directRoot, "height-940611.leaf-proof.json");
  const directStatusApiRoot = path.join(directRoot, "status-api");
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
  createProofV1(directData, "db0-proof-v1");
  createProofV1(directData, "db1-proof-v1");
  const directServicePolicy = path.join(directRoot, "service-policy.bin");
  const directSwaps = path.join(directRoot, "swaps");
  const directSealedRoot = path.join(directData, "pir2-sealed");
  write(directServicePolicy, "fixture policy\n");
  write(directSwaps, "Filename\tType\tSize\tUsed\tPriority\n");
  writeSealedStartup(directSealedRoot, "ready", 1, directServicePolicy);
  for (const relative of [
    "release.bin",
    "credentials.envelope.bin",
    "provider-accounting-authorization.bin",
    "issuer-accounting-approval.bin",
    "bat-acceptance-class.bin",
  ]) {
    write(path.join(directSealedRoot, relative), `${relative} fixture\n`);
  }
  write(
    path.join(directData, "databases.toml"),
    `[[database]]\nname = "main"\ntype = "full"\npath = "db0-runtime"\nproof_dir = "db0-proof-v1"\nproof_v2_dir = "db0-proof"\nbase_height = 0\nheight = 948454\n\n[[database]]\nname = "delta"\ntype = "delta"\npath = "db1-runtime"\nproof_dir = "db1-proof-v1"\nproof_v2_dir = "db1-proof"\nbase_height = 940611\nheight = 948454\n`,
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
printf 'oram:%s\n' "$out" >> "${directEvents}"
`,
  );
  write(
    directUnifiedServer,
    `#!/bin/sh
printf '%s\n' "$@" > "${unifiedArgs}.latest"
preflight=false
receipt=
marker=
boot_id=
identity_cert=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pir2-snp-sealed-preflight-only) preflight=true; shift ;;
    --pir2-snp-sealed-receipt) receipt=$2; shift 2 ;;
    --pir2-snp-sealed-marker) marker=$2; shift 2 ;;
    --pir2-snp-sealed-current-boot-id-hex) boot_id=$2; shift 2 ;;
    --pir2-snp-sealed-identity-cert) identity_cert=$2; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$preflight" = true ]; then
  [ -s "$identity_cert" ] || exit 2
  [ ! -e "$receipt" ] || exit 2
  [ ! -e "$marker" ] || exit 2
  printf 'ready-preflight\n' >> "${directEvents}"
  printf 'fixture ready receipt\n' > "$receipt"
  {
    printf 'schema=bitcoinpir-pir2-sealed-inert-success-v1\n'
    printf 'phase=ready\n'
    printf 'boot_id=%s\n' "$boot_id"
    printf 'receipt_digest=%s\n' '${"45".repeat(32)}'
    printf 'exit_code=42\n'
  } > "$marker"
  exit 42
fi
mv "${unifiedArgs}.latest" "${unifiedArgs}"
printf 'final-ready\n' >> "${directEvents}"
printf started >> "${unifiedStarts}"
printf ready > "${readySignal}"
printf 'fixture server stdout\n'
printf 'fixture server stderr\n' >&2
sleep 2
`,
  );
  write(
    path.join(fixtureBin, "nc"),
    `#!/bin/sh
case " $* " in *" -z "*) exit 64 ;; esac
[ -e "${readySignal}" ] && exit 0
exit 1
`,
  );
  writeFileSync(bootIdFile, "11111111-1111-1111-1111-111111111111\n");
  chmodSync(directOramctl, 0o755);
  chmodSync(directUnifiedServer, 0o755);
  chmodSync(path.join(fixtureBin, "nc"), 0o755);

  const directRunScript = path.join(directRoot, "unified-server-run.sh");
  const directTransformed = readFileSync(tier3RunScript, "utf8")
    .replaceAll("/home/pir/data", directData)
    .replace("SERVICE_POLICY_PATH=/etc/bitcoinpir/payment/service-policy.bin", `SERVICE_POLICY_PATH=${directServicePolicy}`)
    .replace("/usr/share/bitcoinpir/proofs/height-940611.leaf-proof.json", directBhtmProof)
    .replace("ORAMCTL=/usr/local/bin/oramctl", `ORAMCTL=${directOramctl}`)
    .replaceAll("/run/bitcoinpir-oram-status-api", directStatusApiRoot)
    .replace("start_direct_oram_status_api\nstart_total_watchdog", ":\nstart_total_watchdog")
    .replace(
      'stop_direct_oram_status_api || fatal "Direct ORAM status API did not release port 8091"\nremove_direct_oram_status_api_root || fatal "failed to remove Direct ORAM status API root"',
      ":\nremove_direct_oram_status_api_root",
    )
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
    .replace("ORAM_TOTAL_MAX_SECONDS=900", "ORAM_TOTAL_MAX_SECONDS=8")
    .replace("ORAM_HEARTBEAT_INTERVAL_SECONDS=15", "ORAM_HEARTBEAT_INTERVAL_SECONDS=1")
    .replace("ORAM_HEARTBEAT_DEADLINE_SECONDS=90", "ORAM_HEARTBEAT_DEADLINE_SECONDS=3")
    .replace("ORAM_KILL_GRACE_SECONDS=5", "ORAM_KILL_GRACE_SECONDS=0")
    .replace('ORAM_PAGE_KEY_HEX="$(random_seed_hex)"', "ORAM_PAGE_KEY_HEX=test-page-key")
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
  const directEnv = {
    ...process.env,
    BPIR_ORAM_BOOT_ID_FILE: bootIdFile,
    BPIR_PIR2_PROC_SWAPS: directSwaps,
    BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: path.join(directRoot, "trusted-attempt"),
    PATH: `${fixtureBin}:${process.env.PATH}`,
  };
  const completeStartup = readFileSync(path.join(directSealedRoot, "startup.env"), "utf8");
  writeFileSync(
    path.join(directSealedRoot, "startup.env"),
    completeStartup.replace(/^class_digest_hex=.*\n/m, ""),
  );
  const partialSealedConfig = run("sh", [directRunScript], { env: directEnv });
  assert.notEqual(partialSealedConfig.status, 0, partialSealedConfig.stdout + partialSealedConfig.stderr);
  assert.match(partialSealedConfig.stderr, /exactly one non-empty class_digest_hex/);
  assert.equal(existsSync(directMarker), false, "ORAM must not run with partial sealed config");
  assert.equal(existsSync(unifiedStarts), false, "server must not run with partial sealed config");
  writeFileSync(path.join(directSealedRoot, "startup.env"), completeStartup);
  const missingReadyArtifact = run("sh", [directRunScript], { env: directEnv });
  assert.notEqual(missingReadyArtifact.status, 0, missingReadyArtifact.stdout + missingReadyArtifact.stderr);
  assert.match(missingReadyArtifact.stderr, /Ready preflight failed with exit 2/);
  assert.equal(existsSync(directMarker), false, "ORAM must not run before Ready public artifacts pass");
  assert.equal(existsSync(unifiedStarts), false, "final server must not run before Ready preflight");
  write(path.join(directSealedRoot, "identity.cert"), "identity certificate fixture\n");
  const directSuccess = run("sh", [directRunScript], { env: directEnv });
  assert.equal(directSuccess.status, 0, directSuccess.stdout + directSuccess.stderr);
  const directCalls = readFileSync(directMarker, "utf8");
  assert.match(directCalls, /db0-mainnet-948454/);
  assert.match(directCalls, /db1-delta-940611-948454/);
  const finalArgs = readFileSync(unifiedArgs, "utf8");
  assert.match(finalArgs, /--direct-oram-db\n0=.*db0-mainnet-948454/);
  assert.match(finalArgs, /--direct-oram-db\n1=.*db1-delta-940611-948454/);
  assert.match(finalArgs, /--pir2-snp-sealed-require-ready/);
  assert.match(finalArgs, /--service-storeless-bat-v2-policy-digest-hex/);
  assert.equal(
    (finalArgs.match(/--service-storeless-bat-v2-retained-policy/g) ?? []).length,
    0,
  );
  assert.equal((finalArgs.match(/--service-storeless-bat-v2-class/g) ?? []).length, 1);
  assert.doesNotMatch(finalArgs, /(?:--identity-key-path|--service-shared-clearing-key|--service-storeless-bat-v2-pir1-clearing-key)/);
  assert.deepEqual(
    readFileSync(directEvents, "utf8").trim().split("\n").map((event) =>
      event
        .replace(/^oram:.*db0-mainnet-948454$/, "oram-db0")
        .replace(/^oram:.*db1-delta-940611-948454$/, "oram-db1")
    ),
    ["ready-preflight", "oram-db0", "oram-db1", "final-ready"],
  );
  for (const label of ["mainnet-948454", "delta-940611-948454"]) {
    assert.match(
      readFileSync(path.join(directData, "oram-boot-logs", `${label}.status.env`), "utf8"),
      /status=success[\s\S]*reason=none/,
    );
  }
  assert.match(
    readFileSync(path.join(directData, "oram-boot-logs", "direct-oram-bootstrap.status.env"), "utf8"),
    /status=ready[\s\S]*phase=server-readiness[\s\S]*reason=port-ready/,
  );
  const runtimeLog = path.join(directData, "oram-boot-logs", "unified-server.runtime.log");
  const runtimeLogText = readFileSync(runtimeLog, "utf8");
  assert.match(runtimeLogText, /attempt boot_id=11111111-1111-1111-1111-111111111111/);
  assert.match(runtimeLogText, /fixture server stdout[\s\S]*fixture server stderr/);
  assert.doesNotMatch(runtimeLogText, /test-page-key/);
  assert.equal(statSync(runtimeLog).mode & 0o777, 0o600);
  assert.equal(readFileSync(unifiedStarts, "utf8"), "started");
  const firstBootHex = "11111111111111111111111111111111";
  const readyPreflightReceipt = path.join(
    directSealedRoot,
    `receipts/ready-preflight-${firstBootHex}.bin`,
  );
  const readyPreflightToken = path.join(
    directEnv.BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT,
    `ready-preflight-${firstBootHex}.env`,
  );
  const readyPreflightTokenText = readFileSync(readyPreflightToken, "utf8");
  assert.match(readyPreflightTokenText, /kind=ready-preflight\nphase=ready\n/);
  const directArtifactSet = path.join(directSealedRoot, "public-artifact-set.env");
  assert.match(
    readyPreflightTokenText,
    new RegExp(`artifact_set_sha256=${sha256(readFileSync(directArtifactSet))}`),
  );
  const trustedArtifactSet = path.join(
    directEnv.BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT,
    `public-artifact-set-${firstBootHex}.env`,
  );
  assert.equal(readFileSync(trustedArtifactSet, "utf8"), readFileSync(directArtifactSet, "utf8"));
  assert.equal(statSync(trustedArtifactSet).mode & 0o777, 0o600);
  assert.match(
    readyPreflightTokenText,
    new RegExp(`receipt_file_sha256=${sha256(readFileSync(readyPreflightReceipt))}`),
  );

  const callsBeforeSameBootRetry = readFileSync(directMarker, "utf8");
  const sameBootRetry = run("sh", [directRunScript], { env: directEnv });
  assert.equal(sameBootRetry.status, 0, sameBootRetry.stdout + sameBootRetry.stderr);
  assert.equal(readFileSync(directMarker, "utf8"), callsBeforeSameBootRetry);
  assert.equal(readFileSync(unifiedStarts, "utf8"), "started");
  assert.match(sameBootRetry.stderr, /already published.*refusing destructive retry/);

  const directStartupPath = path.join(directSealedRoot, "startup.env");
  const directStartup = readFileSync(directStartupPath, "utf8");
  writeFileSync(directStartupPath, directStartup.replace("ordinal=1\n", "ordinal=2\n"));
  const crossAttemptReady = run("sh", [directRunScript], { env: directEnv });
  assert.notEqual(crossAttemptReady.status, 0, crossAttemptReady.stdout + crossAttemptReady.stderr);
  assert.match(crossAttemptReady.stderr, /token does not match the current attempt/);
  assert.equal(readFileSync(directMarker, "utf8"), callsBeforeSameBootRetry);
  writeFileSync(directStartupPath, directStartup);

  rmSync(readyPreflightToken);
  const eventsBeforeAuditOnlyReady = readFileSync(directEvents, "utf8");
  const auditOnlyReady = run("sh", [directRunScript], { env: directEnv });
  assert.notEqual(auditOnlyReady.status, 0, auditOnlyReady.stdout + auditOnlyReady.stderr);
  assert.match(auditOnlyReady.stderr, /Ready preflight failed with exit 2/);
  assert.equal(
    readFileSync(directEvents, "utf8"),
    eventsBeforeAuditOnlyReady,
    "persistent Ready audit files must not skip or replace the measured child",
  );
  assert.equal(existsSync(readyPreflightToken), false);

  writeFileSync(bootIdFile, "22222222-2222-2222-2222-222222222222\n");
  rmSync(readySignal);
  const newBootRun = run("sh", [directRunScript], { env: directEnv });
  assert.equal(newBootRun.status, 0, newBootRun.stdout + newBootRun.stderr);
  assert.notEqual(readFileSync(directMarker, "utf8"), callsBeforeSameBootRetry);
  assert.equal(readFileSync(directMarker, "utf8").trim().split("\n").length, 4);
  assert.equal(readFileSync(unifiedStarts, "utf8"), "startedstarted");

  const timeoutUnifiedServer = path.join(directRoot, "timeout-unified_server");
  write(
    timeoutUnifiedServer,
    `#!/bin/sh
preflight=false
receipt=
marker=
boot_id=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pir2-snp-sealed-preflight-only) preflight=true; shift ;;
    --pir2-snp-sealed-receipt) receipt=$2; shift 2 ;;
    --pir2-snp-sealed-marker) marker=$2; shift 2 ;;
    --pir2-snp-sealed-current-boot-id-hex) boot_id=$2; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$preflight" = true ]; then
  printf 'fixture timeout preflight receipt\n' > "$receipt"
  {
    printf 'schema=bitcoinpir-pir2-sealed-inert-success-v1\n'
    printf 'phase=ready\n'
    printf 'boot_id=%s\n' "$boot_id"
    printf 'receipt_digest=%s\n' '${"47".repeat(32)}'
    printf 'exit_code=42\n'
  } > "$marker"
  exit 42
fi
printf 'timeout server stdout\\n'
printf 'timeout server stderr\\n' >&2
exec sleep 5
`,
  );
  chmodSync(timeoutUnifiedServer, 0o755);
  writeFileSync(bootIdFile, "33333333-3333-3333-3333-333333333333\n");
  rmSync(readySignal, { force: true });
  const timeoutRunScript = path.join(directRoot, "unified-server-timeout-run.sh");
  writeFileSync(
    timeoutRunScript,
    directTransformed
      .replace(`UNIFIED_SERVER=${directUnifiedServer}`, `UNIFIED_SERVER=${timeoutUnifiedServer}`)
      .replace("ORAM_TOTAL_MAX_SECONDS=8", "ORAM_TOTAL_MAX_SECONDS=1"),
  );
  chmodSync(timeoutRunScript, 0o755);
  const serverReadinessTimeout = run("sh", [timeoutRunScript], { env: directEnv });
  assert.notEqual(serverReadinessTimeout.status, 0, serverReadinessTimeout.stdout + serverReadinessTimeout.stderr);
  assert.match(
    readFileSync(path.join(directData, "oram-boot-logs", "direct-oram-bootstrap.status.env"), "utf8"),
    /status=timed_out[\s\S]*phase=server-readiness[\s\S]*reason=total-timeout[\s\S]*timeout_seconds=1/,
  );
  assert.doesNotMatch(readFileSync(runtimeLog, "utf8"), /test-page-key/);

  const guardRoot = path.join(tempRoot, "runit-guard");
  const guardState = path.join(guardRoot, "state");
  const guardStatus = path.join(guardRoot, "status");
  const guardService = path.join(guardRoot, "service");
  const guardAttemptRoot = path.join(guardRoot, "trusted-attempt");
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
    BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT: guardAttemptRoot,
  };
  const sealedGuardRoot = path.join(guardRoot, "pir2-sealed");
  const sealedGuardBootId = path.join(guardRoot, "sealed-boot-id");
  const sealedGuardBootHex = "55555555555555555555555555555555";
  writeFileSync(sealedGuardBootId, "55555555-5555-5555-5555-555555555555\n");
  write(
    path.join(sealedGuardRoot, `receipts/inert-${sealedGuardBootHex}.bin`),
    "fixture receipt\n",
  );
  write(
    path.join(sealedGuardRoot, `markers/inert-${sealedGuardBootHex}.env`),
    `schema=bitcoinpir-pir2-sealed-inert-success-v1
phase=enroll
boot_id=${sealedGuardBootHex}
receipt_digest=${"55".repeat(32)}
exit_code=42
`,
  );
  const forgedPersistentFinish = run("sh", [tier3FinishScript, "42", "0"], {
    env: {
      ...guardEnv,
      BPIR_ORAM_BOOT_ID_FILE: sealedGuardBootId,
      BPIR_PIR2_SNP_SEALED_ROOT: sealedGuardRoot,
    },
  });
  assert.equal(forgedPersistentFinish.status, 0, forgedPersistentFinish.stdout + forgedPersistentFinish.stderr);
  assert.equal(existsSync(svLog), false, "persistent marker/receipt must never authorize finish down");
  assert.equal(readFileSync(path.join(guardState, "failure_count"), "utf8"), "1\n");

  rmSync(guardState, { recursive: true, force: true });
  write(
    path.join(guardAttemptRoot, `terminal-${sealedGuardBootHex}.env`),
    authoritativeAttemptToken({
      kind: "terminal",
      phase: "enroll",
      bootIdHex: sealedGuardBootHex,
      ordinal: 2,
      receiptProtocolDigest: "55".repeat(32),
      receiptFileSha256: "56".repeat(32),
    }),
  );
  const inertFinish = run("sh", [tier3FinishScript, "42", "0"], {
    env: {
      ...guardEnv,
      BPIR_ORAM_BOOT_ID_FILE: sealedGuardBootId,
    },
  });
  assert.equal(inertFinish.status, 0, inertFinish.stdout + inertFinish.stderr);
  assert.equal(readFileSync(svLog, "utf8"), `-w 1 down ${guardService}\n`);
  assert.equal(existsSync(path.join(guardState, "failure_count")), false);
  assert.match(
    readFileSync(path.join(guardStatus, "unified-server-runit.status"), "utf8"),
    /status=restart_suppressed[\s\S]*failure_count=0[\s\S]*exit_code=42[\s\S]*reason=pir2-sealed-inert-success/,
  );

  rmSync(svLog);
  rmSync(path.join(guardAttemptRoot, `terminal-${sealedGuardBootHex}.env`));
  write(
    path.join(guardAttemptRoot, `ready-preflight-${sealedGuardBootHex}.env`),
    authoritativeAttemptToken({
      kind: "ready-preflight",
      phase: "ready",
      bootIdHex: sealedGuardBootHex,
      receiptProtocolDigest: "57".repeat(32),
      receiptFileSha256: "58".repeat(32),
    }),
  );
  rmSync(path.join(sealedGuardRoot, `markers/inert-${sealedGuardBootHex}.env`));
  write(
    path.join(sealedGuardRoot, `receipts/ready-preflight-${sealedGuardBootHex}.bin`),
    "fixture ready preflight receipt\n",
  );
  write(
    path.join(sealedGuardRoot, `markers/ready-preflight-${sealedGuardBootHex}.env`),
    `schema=bitcoinpir-pir2-sealed-inert-success-v1
phase=ready
boot_id=${sealedGuardBootHex}
receipt_digest=${"56".repeat(32)}
exit_code=42
`,
  );
  const unbound42 = run("sh", [tier3FinishScript, "42", "0"], {
    env: {
      ...guardEnv,
      BPIR_ORAM_BOOT_ID_FILE: sealedGuardBootId,
    },
  });
  assert.equal(unbound42.status, 0, unbound42.stdout + unbound42.stderr);
  assert.equal(readFileSync(path.join(guardState, "failure_count"), "utf8"), "1\n");
  assert.equal(
    existsSync(svLog),
    false,
    "Ready-preflight token must not make finish treat exit 42 as terminal success",
  );
  rmSync(path.join(guardAttemptRoot, `ready-preflight-${sealedGuardBootHex}.env`));
  rmSync(guardState, { recursive: true, force: true });
  write(
    path.join(guardAttemptRoot, `terminal-${sealedGuardBootHex}.env`),
    "schema=bitcoinpir-pir2-sealed-authoritative-attempt-v1\nkind=terminal\n",
  );
  const partialTerminalToken = run("sh", [tier3FinishScript, "42", "0"], {
    env: {
      ...guardEnv,
      BPIR_ORAM_BOOT_ID_FILE: sealedGuardBootId,
    },
  });
  assert.equal(partialTerminalToken.status, 0, partialTerminalToken.stdout + partialTerminalToken.stderr);
  assert.equal(readFileSync(path.join(guardState, "failure_count"), "utf8"), "1\n");
  assert.equal(existsSync(svLog), false, "partial terminal token must stay on bounded retry");
  rmSync(path.join(guardAttemptRoot, `terminal-${sealedGuardBootHex}.env`));
  rmSync(guardState, { recursive: true, force: true });
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

  const markerBootId = path.join(guardRoot, "boot_id");
  const markerPath = path.join(guardStatus, "oram-published.boot-id.env");
  rmSync(guardState, { recursive: true, force: true });
  writeFileSync(markerBootId, "44444444-4444-4444-4444-444444444444\n");
  write(
    markerPath,
    "boot_id=44444444-4444-4444-4444-444444444444\nstatus=published\npublished_at=fixture\n",
  );
  const fixtureFinishScript = path.join(guardRoot, "unified-server-finish.sh");
  writeFileSync(
    fixtureFinishScript,
    readFileSync(tier3FinishScript, "utf8")
      .replaceAll("/home/pir/data/oram-boot-logs", guardStatus),
  );
  chmodSync(fixtureFinishScript, 0o755);
  const publishedAbort = run("sh", [fixtureFinishScript, "134", "6"], {
    env: {
      ...guardEnv,
      BPIR_ORAM_BOOT_ID_FILE: markerBootId,
      BPIR_ORAM_PUBLISHED_MARKER: markerPath,
    },
  });
  assert.equal(publishedAbort.status, 0, publishedAbort.stdout + publishedAbort.stderr);
  assert.equal(readFileSync(svLog, "utf8"), `-w 1 down ${guardService}\n`);
  assert.match(
    readFileSync(path.join(guardStatus, "unified-server-runit.status"), "utf8"),
    /status=restart_suppressed[\s\S]*failure_count=1[\s\S]*action=down[\s\S]*reason=oram-published-same-boot/,
  );

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
