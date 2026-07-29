#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import tls from "node:tls";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  OVERLAY_COLLECTOR,
  buildOverlayCandidateFromRendered,
  canonicalJson,
  computeApprovedOverlayPlanSha256,
  parseStrictJson,
  validateOverlayPlan,
  validateOverlayReceipt,
} from "./payment-v1-integrated-caddy-overlay-gate.mjs";

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_COMMAND_BYTES = 8 * 1024 * 1024;
const TARGET_CONFIG = "/etc/caddy/Caddyfile";
const TARGET_UNIT = "bhtm-caddy.service";
const SOURCE_FAIR_UNIT = "bitcoinpir-payment-v1-source-fair-edge.service";
const RENAME_EXCHANGE_HELPER =
  "/opt/bitcoinpir/payment-v1-rename-exchange/@OVERLAY_EXCHANGE_SHA256@/payment-v1-rename-exchange";
const RENAME_EXCHANGE_MANIFEST =
  "/etc/bitcoinpir/payment-v1/integrated-existing-bhtm-caddy/rename-exchange.sha256";
const LOCK_OWNER = "owner.json";
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export const OVERLAY_STATE_FILES = Object.freeze({
  aborted: "50-aborted-before-install.json",
  committed: "50-committed.json",
  exchanged: "10-exchanged.json",
  prepared: "00-prepared.json",
  reloaded: "20-reloaded.json",
  rollbackExchanged: "30-rollback-exchanged.json",
  rollbackReloaded: "40-rollback-reloaded.json",
  rolledBack: "50-rolled-back.json",
});

const PHASE_TO_FILE = Object.freeze({
  "aborted-before-install": OVERLAY_STATE_FILES.aborted,
  committed: OVERLAY_STATE_FILES.committed,
  exchanged: OVERLAY_STATE_FILES.exchanged,
  prepared: OVERLAY_STATE_FILES.prepared,
  reloaded: OVERLAY_STATE_FILES.reloaded,
  "rollback-exchanged": OVERLAY_STATE_FILES.rollbackExchanged,
  "rollback-reloaded": OVERLAY_STATE_FILES.rollbackReloaded,
  "rolled-back": OVERLAY_STATE_FILES.rolledBack,
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fail(message) {
  throw new Error(message);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} keys drifted`);
  }
}

function exactRegularSnapshot(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} drifted from the approved regular-file pin`);
}

function exactGeneration(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} process generation drifted`);
}

function assertRuntimePath(actual, expected, label) {
  if (!same(actual, expected)) fail(`${label} runtime path drifted`);
}

function assertFinalConfig(snapshot, digest, label) {
  if (
    snapshot.path !== TARGET_CONFIG ||
    snapshot.sha256 !== digest ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0644" ||
    snapshot.nlink !== 1
  ) {
    fail(`${label} is not the exact root-owned single-link Caddyfile generation`);
  }
}

function assertExchangeIdentity(actual, expected, path, label) {
  const keys = [
    "device",
    "gid",
    "inode",
    "mode",
    "mtime_ns",
    "nlink",
    "sha256",
    "size",
    "uid",
  ];
  if (actual.path !== path || keys.some((key) => actual[key] !== expected[key])) {
    fail(`${label} does not contain the exact exchanged inode and bytes`);
  }
}

function assertManifest(manifestBytes, helperPin) {
  const expected = Buffer.from(`${helperPin.sha256}  ${helperPin.path}\n`, "utf8");
  if (!Buffer.from(manifestBytes).equals(expected)) {
    fail("rename-exchange manifest does not bind only the exact plan-pinned helper");
  }
}

async function collectPinnedState(plan, ops, label, { requirePreimage = true } = {}) {
  const pins = [
    [plan.runtime.node_binary, `${label} Node runtime`],
    [plan.runtime.gate, `${label} overlay gate`],
    [plan.runtime.executor, `${label} overlay executor`],
    [plan.runtime.exchange_helper, `${label} rename-exchange helper`],
    [plan.runtime.exchange_manifest, `${label} rename-exchange manifest`],
    [plan.runtime.managed_block, `${label} rendered managed block`],
    [plan.target.binary, `${label} Caddy binary`],
    [plan.target.unit_fragment, `${label} Caddy unit fragment`],
    [plan.source_fair.haproxy_binary, `${label} HAProxy binary`],
    [plan.source_fair.haproxy_config, `${label} HAProxy config`],
    [plan.source_fair.unit_fragment, `${label} HAProxy unit fragment`],
    ...plan.tls_dependencies.map((entry, index) => [
      entry.pin,
      `${label} TLS dependency ${index}`,
    ]),
  ];
  const files = new Map();
  const snapshots = new Map();
  for (const [pin, pinLabel] of pins) {
    const observed = await ops.readRegular(pin.path);
    exactRegularSnapshot(observed.snapshot, pin, pinLabel);
    files.set(pin.path, Buffer.from(observed.bytes));
    snapshots.set(pin.path, observed.snapshot);
  }
  assertManifest(files.get(plan.runtime.exchange_manifest.path), plan.runtime.exchange_helper);
  const config = await ops.readRegular(plan.target.config_preimage.path);
  if (requirePreimage) {
    exactRegularSnapshot(config.snapshot, plan.target.config_preimage, `${label} Caddyfile preimage`);
  }
  const caddyGeneration = await ops.readUnitGeneration(TARGET_UNIT);
  exactGeneration(caddyGeneration, plan.target.unit_generation, `${label} Caddy`);
  const sourceFairGeneration = await ops.readUnitGeneration(SOURCE_FAIR_UNIT);
  exactGeneration(sourceFairGeneration, plan.source_fair.unit_generation, `${label} source-fair HAProxy`);
  for (const [index, expected] of plan.source_fair.runtime_paths.entries()) {
    assertRuntimePath(
      await ops.readRuntimePath(expected.path),
      expected,
      `${label} source_fair.runtime_paths[${index}]`,
    );
  }
  for (const [index, dependency] of plan.tls_dependencies.entries()) {
    const parent = await ops.readDirectory(dependency.parent.path);
    if (!same(parent, dependency.parent)) fail(`${label} TLS dependency ${index} parent drifted`);
  }
  const configParent = await ops.readDirectory(plan.target.config_parent.path);
  if (!same(configParent, plan.target.config_parent)) fail(`${label} Caddy config parent drifted`);
  return { caddyGeneration, config, files, snapshots, sourceFairGeneration };
}

function receiptSnapshot(plan, state, configSnapshot) {
  return {
    binary: state.snapshots.get(plan.target.binary.path),
    config: configSnapshot,
    source_fair_generation: state.sourceFairGeneration,
    target_generation: state.caddyGeneration,
    unit_fragment: state.snapshots.get(plan.target.unit_fragment.path),
  };
}

function baseReceipt({
  approvedPlanSha256,
  backup,
  before,
  healthResults,
  host,
  installation,
  outcome,
  plan,
  preparation,
  reload,
  rollback,
  after,
}) {
  return {
    after,
    approved_plan_sha256: approvedPlanSha256,
    backup,
    before,
    collector: OVERLAY_COLLECTOR,
    health_results: healthResults,
    host,
    installation,
    outcome,
    preparation,
    reload,
    rollback,
    schema_version: 1,
    transaction_id: plan.transaction_id,
  };
}

function noRollback() {
  return {
    attempted: false,
    directory_fsync: false,
    exact_candidate_swapped_out: false,
    exact_preimage_restored: false,
    exchanged: false,
    reload_exit_status: null,
  };
}

function stateRecord(plan, approvedPlanSha256, phase, previousPhase, extra = {}) {
  return {
    approved_plan_sha256: approvedPlanSha256,
    phase,
    previous_phase: previousPhase,
    schema_version: 1,
    transaction_id: plan.transaction_id,
    ...extra,
  };
}

async function writeState(ops, plan, record) {
  const filename = PHASE_TO_FILE[record.phase];
  if (filename === undefined) fail(`unknown transaction phase ${record.phase}`);
  await ops.writeState(
    plan.transaction.state_directory,
    filename,
    Buffer.from(canonicalJson(record), "utf8"),
  );
}

function receiptDigest(receipt) {
  return sha256(Buffer.from(canonicalJson(receipt), "utf8"));
}

async function writeReceipt(ops, plan, approvedPlanSha256, receipt) {
  validateOverlayReceipt({ approvedPlanSha256, plan, receipt });
  const bytes = Buffer.from(canonicalJson(receipt), "utf8");
  try {
    await ops.writeReceipt(
      plan.transaction.receipt_pending_path,
      plan.transaction.receipt_path,
      bytes,
      plan.runtime.exchange_helper,
    );
  } catch (error) {
    // An fsync/close error can be reported after the exact receipt reached
    // durable storage. Re-read the no-follow entry before deciding whether a
    // rollback is still permitted.
    const observed = await ops.readOptionalRegular(plan.transaction.receipt_path);
    if (observed === null || !observed.bytes.equals(bytes)) throw error;
    const pending = await ops.readOptionalRegular(plan.transaction.receipt_pending_path);
    if (pending !== null && pending.bytes.equals(bytes)) {
      await ops.removeIfExact(plan.transaction.receipt_pending_path, pending.snapshot);
    }
  }
  return sha256(bytes);
}

export class OverlayTransactionError extends Error {
  constructor(message, { cause, phase, receipt } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "OverlayTransactionError";
    this.phase = phase;
    this.receipt = receipt;
  }
}

async function releasePreservingPrimary(release, operation) {
  let value;
  let primary;
  try {
    value = await operation();
  } catch (error) {
    primary = error;
  }
  try {
    await release();
  } catch (releaseError) {
    if (primary !== undefined) {
      primary.lockReleaseError = releaseError;
    } else {
      primary = new OverlayTransactionError(
        `transaction completed but lock release failed closed: ${releaseError.message}`,
        { cause: releaseError, phase: "lock-release-failed", receipt: value },
      );
    }
  }
  if (primary !== undefined) throw primary;
  return value;
}

function installationRecord(plan) {
  return {
    candidate_path: plan.transaction.candidate_path,
    config_parent_fsync: true,
    exchange_helper_sha256: plan.runtime.exchange_helper.sha256,
    exchanged: true,
    live_candidate_verified: true,
    same_filesystem: true,
    swapped_out_preimage_verified: true,
  };
}

async function verifyInstalledPair(plan, ops, candidateSnapshot) {
  const live = await ops.readRegular(TARGET_CONFIG);
  const swapped = await ops.readRegular(plan.transaction.candidate_path);
  assertExchangeIdentity(live.snapshot, candidateSnapshot, TARGET_CONFIG, "live exchanged candidate");
  assertExchangeIdentity(
    swapped.snapshot,
    plan.target.config_preimage,
    plan.transaction.candidate_path,
    "swapped-out Caddyfile preimage",
  );
  return { live, swapped };
}

async function readExchangePair(plan, ops) {
  return {
    live: await ops.readRegular(TARGET_CONFIG),
    swapped: await ops.readRegular(plan.transaction.candidate_path),
  };
}

async function verifyRolledBackPair(plan, ops, candidateSnapshot) {
  const live = await ops.readRegular(TARGET_CONFIG);
  const swapped = await ops.readRegular(plan.transaction.candidate_path);
  assertExchangeIdentity(live.snapshot, plan.target.config_preimage, TARGET_CONFIG, "restored Caddyfile preimage");
  assertExchangeIdentity(
    swapped.snapshot,
    candidateSnapshot,
    plan.transaction.candidate_path,
    "swapped-out managed candidate",
  );
  return { live, swapped };
}

async function exchange(ops, plan) {
  await ops.exchange(
    plan.transaction.candidate_path,
    TARGET_CONFIG,
    plan.runtime.exchange_helper,
  );
}

async function exchangeInstalledPairForRollback(plan, ops, candidateSnapshot) {
  await verifyInstalledPair(plan, ops, candidateSnapshot);
  await exchange(ops, plan);
  const observedExchange = await readExchangePair(plan, ops);
  try {
    assertExchangeIdentity(
      observedExchange.live.snapshot,
      plan.target.config_preimage,
      TARGET_CONFIG,
      "rollback restored Caddyfile preimage",
    );
    assertExchangeIdentity(
      observedExchange.swapped.snapshot,
      candidateSnapshot,
      plan.transaction.candidate_path,
      "rollback swapped-out managed candidate",
    );
  } catch (verificationError) {
    try {
      await exchange(ops, plan);
      const restored = await readExchangePair(plan, ops);
      assertExchangeIdentity(
        restored.live.snapshot,
        observedExchange.swapped.snapshot,
        TARGET_CONFIG,
        "rollback-rejected restored live entry",
      );
      assertExchangeIdentity(
        restored.swapped.snapshot,
        observedExchange.live.snapshot,
        plan.transaction.candidate_path,
        "rollback-rejected restored candidate entry",
      );
    } catch (restoreError) {
      throw new OverlayTransactionError(
        `rollback exchange verification failed and exact restoration is not proven: ${restoreError.message}`,
        { cause: restoreError, phase: "rollback-exchange-restore-failed" },
      );
    }
    throw new OverlayTransactionError(
      `rollback exchange verification failed; exact pre-exchange entries were restored without reload: ${verificationError.message}`,
      { cause: verificationError, phase: "rollback-exchange-rejected" },
    );
  }
}

async function rollbackInstalled({
  approvedPlanSha256,
  candidateSnapshot,
  context,
  ops,
  plan,
  previousPhase,
  reload,
}) {
  await exchangeInstalledPairForRollback(plan, ops, candidateSnapshot);
  await writeState(
    ops,
    plan,
    stateRecord(plan, approvedPlanSha256, "rollback-exchanged", previousPhase),
  );
  const rollbackReload = await ops.run(plan.transaction.reload_argv, {
    captureStdout: false,
    maxBytes: MAX_COMMAND_BYTES,
    timeoutMs: 30_000,
  });
  if (rollbackReload.status !== 0) fail("rollback reload failed");
  const restoredState = await collectPinnedState(plan, ops, "post-rollback", {
    requirePreimage: false,
  });
  const finalConfig = await ops.readRegular(TARGET_CONFIG);
  assertFinalConfig(finalConfig.snapshot, plan.target.config_preimage.sha256, "post-rollback Caddyfile");
  const rollback = {
    attempted: true,
    directory_fsync: true,
    exact_candidate_swapped_out: true,
    exact_preimage_restored: true,
    exchanged: true,
    reload_exit_status: rollbackReload.status,
  };
  const after = receiptSnapshot(plan, restoredState, finalConfig.snapshot);
  await writeState(
    ops,
    plan,
    stateRecord(plan, approvedPlanSha256, "rollback-reloaded", "rollback-exchanged", {
      after,
      rollback,
    }),
  );
  const receipt = baseReceipt({
    after,
    approvedPlanSha256,
    backup: context.backup,
    before: context.before,
    healthResults: [],
    host: context.host,
    installation: context.installation,
    outcome: "rolled-back",
    plan,
    preparation: context.preparation,
    reload,
    rollback,
  });
  const digest = await writeReceipt(ops, plan, approvedPlanSha256, receipt);
  try {
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "rolled-back", "rollback-reloaded", {
        receipt_sha256: digest,
      }),
    );
    await ops.removeIfExact(plan.transaction.candidate_path, candidateSnapshot);
  } catch (error) {
    throw new OverlayTransactionError(
      `rolled-back receipt is durable; explicit recovery must finalize cleanup: ${error.message}`,
      { cause: error, phase: "rollback-finalization-failed", receipt },
    );
  }
  return receipt;
}

async function executeLocked({ approvedPlanSha256, ops, plan }) {
  await ops.initializeStateDirectory(plan.transaction.state_directory);
  let candidateSnapshot;
  let prepared = false;
  let exchanged = false;
  let previousPhase = "prepared";
  let context;
  let durableCommitReceipt;
  let reload = {
    argv: structuredClone(plan.transaction.reload_argv),
    exit_status: null,
    restart_invoked: false,
  };
  try {
    const initial = await collectPinnedState(plan, ops, "initial");
    const preimage = Buffer.from(initial.config.bytes);
    const before = receiptSnapshot(plan, initial, initial.config.snapshot);
    const candidate = buildOverlayCandidateFromRendered({
      approvedPlanSha256,
      managedBlockBytes: initial.files.get(plan.runtime.managed_block.path),
      plan,
      preimageBytes: preimage,
    });
    const candidateWrite = await ops.writeExclusive(
      plan.transaction.candidate_path,
      candidate.candidate,
      "0644",
    );
    candidateSnapshot = candidateWrite.snapshot;

    const adapt = await ops.run(plan.transaction.adapt_argv, {
      captureStdout: true,
      maxBytes: MAX_COMMAND_BYTES,
      timeoutMs: 30_000,
    });
    if (adapt.status !== 0) {
      throw new OverlayTransactionError("Caddy adapt failed before installation", { phase: "adapt" });
    }
    const adapted = parseStrictJson(Buffer.from(adapt.stdout).toString("utf8"), "Caddy adapted JSON");
    const adaptedBytes = Buffer.from(canonicalJson(adapted), "utf8");
    await ops.writeExclusive(plan.transaction.adapted_json_path, adaptedBytes, "0400");
    const validate = await ops.run(plan.transaction.validate_argv, {
      captureStdout: false,
      maxBytes: MAX_COMMAND_BYTES,
      timeoutMs: 30_000,
    });
    if (validate.status !== 0) {
      throw new OverlayTransactionError("Caddy validate failed before installation", { phase: "validate" });
    }
    const preparation = {
      adapt_argv: structuredClone(plan.transaction.adapt_argv),
      adapt_exit_status: adapt.status,
      adapted_json_sha256: sha256(adaptedBytes),
      candidate_sha256: candidate.candidateSha256,
      managed_block_sha256: candidate.blockSha256,
      preimage_sha256: candidate.preimageSha256,
      validate_argv: structuredClone(plan.transaction.validate_argv),
      validate_exit_status: validate.status,
    };
    const validatedCandidate = await ops.readRegular(plan.transaction.candidate_path);
    exactRegularSnapshot(validatedCandidate.snapshot, candidateSnapshot, "validated candidate");
    await collectPinnedState(plan, ops, "post-validation");

    const backupWrite = await ops.writeExclusive(plan.transaction.backup_path, preimage, "0400");
    const backup = {
      directory_fsync: backupWrite.directoryFsync,
      exclusive_create: backupWrite.exclusiveCreate,
      file_fsync: backupWrite.fileFsync,
      gid: backupWrite.snapshot.gid,
      mode: backupWrite.snapshot.mode,
      nlink: backupWrite.snapshot.nlink,
      path: backupWrite.snapshot.path,
      sha256: backupWrite.snapshot.sha256,
      uid: backupWrite.snapshot.uid,
    };
    if (
      backup.path !== plan.transaction.backup_path ||
      backup.sha256 !== plan.target.config_preimage.sha256 ||
      backup.uid !== 0 ||
      backup.gid !== 0 ||
      backup.mode !== "0400" ||
      backup.nlink !== 1 ||
      backup.exclusive_create !== true ||
      backup.file_fsync !== true ||
      backup.directory_fsync !== true
    ) {
      fail("backup adapter did not durably create the exact owner-only preimage");
    }
    const finalPreinstall = await ops.readRegular(TARGET_CONFIG);
    exactRegularSnapshot(finalPreinstall.snapshot, plan.target.config_preimage, "final pre-install Caddyfile");
    context = { backup, before, host: await ops.hostIdentity(), preparation };
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "prepared", null, {
        candidate_snapshot: candidateSnapshot,
        context,
      }),
    );
    prepared = true;

    await exchange(ops, plan);
    const observedExchange = await readExchangePair(plan, ops);
    try {
      assertExchangeIdentity(
        observedExchange.live.snapshot,
        candidateSnapshot,
        TARGET_CONFIG,
        "live exchanged candidate",
      );
      assertExchangeIdentity(
        observedExchange.swapped.snapshot,
        plan.target.config_preimage,
        plan.transaction.candidate_path,
        "swapped-out Caddyfile preimage",
      );
    } catch (verificationError) {
      try {
        await exchange(ops, plan);
        const restored = await readExchangePair(plan, ops);
        assertExchangeIdentity(
          restored.live.snapshot,
          observedExchange.swapped.snapshot,
          TARGET_CONFIG,
          "exchange-rejected restored live entry",
        );
        assertExchangeIdentity(
          restored.swapped.snapshot,
          observedExchange.live.snapshot,
          plan.transaction.candidate_path,
          "exchange-rejected restored candidate entry",
        );
      } catch (restoreError) {
        throw new OverlayTransactionError(
          `exchange verification failed and exact restoration is not proven: ${restoreError.message}`,
          { cause: restoreError, phase: "exchange-restore-failed" },
        );
      }
      throw new OverlayTransactionError(
        `exchange verification failed; exact pre-exchange entries were restored without reload: ${verificationError.message}`,
        { cause: verificationError, phase: "exchange-rejected" },
      );
    }
    exchanged = true;
    previousPhase = "exchanged";
    const installation = installationRecord(plan);
    context.installation = installation;
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "exchanged", "prepared", { installation }),
    );

    const reloadResult = await ops.run(plan.transaction.reload_argv, {
      captureStdout: false,
      maxBytes: MAX_COMMAND_BYTES,
      timeoutMs: 30_000,
    });
    reload.exit_status = reloadResult.status;
    if (reloadResult.status !== 0) throw new Error("Caddy reload failed");
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "reloaded", "exchanged", { reload }),
    );
    previousPhase = "reloaded";

    await collectPinnedState(plan, ops, "post-reload", {
      requirePreimage: false,
    });
    const committedConfig = await ops.readRegular(TARGET_CONFIG);
    assertFinalConfig(committedConfig.snapshot, plan.managed_block.candidate_sha256, "post-reload Caddyfile");
    const healthResults = [];
    for (const check of plan.health_checks) {
      const result = await ops.health(check);
      if (
        result.success !== true ||
        result.status !== check.expected_status ||
        result.leaf_certificate_sha256 !== check.leaf_certificate_sha256 ||
        (check.expected_body_sha256 === null
          ? result.body_sha256 !== null
          : result.body_sha256 !== check.expected_body_sha256)
      ) {
        throw new Error(`health check failed for ${check.lane}`);
      }
      healthResults.push({
        body_sha256: result.body_sha256,
        check: structuredClone(check),
        leaf_certificate_sha256: result.leaf_certificate_sha256,
        status: result.status,
        success: true,
      });
    }
    // Health can take seconds. Re-bind the exact file pair and both process
    // generations after the last network probe and immediately before making
    // a committed receipt durable.
    const finalCommittedState = await collectPinnedState(plan, ops, "post-health", {
      requirePreimage: false,
    });
    const finalInstalled = await verifyInstalledPair(plan, ops, candidateSnapshot);
    assertFinalConfig(
      finalInstalled.live.snapshot,
      plan.managed_block.candidate_sha256,
      "post-health Caddyfile",
    );
    const receipt = baseReceipt({
      after: receiptSnapshot(plan, finalCommittedState, finalInstalled.live.snapshot),
      approvedPlanSha256,
      backup,
      before,
      healthResults,
      host: context.host,
      installation,
      outcome: "committed",
      plan,
      preparation,
      reload,
      rollback: noRollback(),
    });
    const digest = await writeReceipt(ops, plan, approvedPlanSha256, receipt);
    durableCommitReceipt = receipt;
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "committed", "reloaded", {
        receipt_sha256: digest,
      }),
    );
    await ops.removeIfExact(plan.transaction.candidate_path, {
      ...plan.target.config_preimage,
      path: plan.transaction.candidate_path,
    });
    return receipt;
  } catch (error) {
    if (durableCommitReceipt !== undefined) {
      throw new OverlayTransactionError(
        `committed receipt is durable; explicit recovery must finalize cleanup: ${error.message}`,
        {
          cause: error,
          phase: "commit-finalization-failed",
          receipt: durableCommitReceipt,
        },
      );
    }
    if (!exchanged) {
      if (prepared) {
        try {
          await writeState(
            ops,
            plan,
            stateRecord(plan, approvedPlanSha256, "aborted-before-install", "prepared"),
          );
        } catch {
          // Durable prepared state plus the exact file pair remains recoverable.
        }
      }
      if (candidateSnapshot !== undefined) {
        try {
          await ops.removeIfExact(plan.transaction.candidate_path, candidateSnapshot);
        } catch {
          // Never mask the primary failure or remove an entry that is no longer ours.
        }
      }
      throw error instanceof OverlayTransactionError
        ? error
        : new OverlayTransactionError(
            `integrated Caddy transaction aborted before installation: ${error.message}`,
            { cause: error, phase: "pre-install" },
          );
    }
    try {
      const receipt = await rollbackInstalled({
        approvedPlanSha256,
        candidateSnapshot,
        context,
        ops,
        plan,
        previousPhase,
        reload,
      });
      throw new OverlayTransactionError(
        `Caddy overlay failed and exact preimage was restored: ${error.message}`,
        { cause: error, phase: "rolled-back", receipt },
      );
    } catch (rollbackError) {
      if (rollbackError instanceof OverlayTransactionError && rollbackError.receipt !== undefined) {
        throw rollbackError;
      }
      throw new OverlayTransactionError(
        `Caddy overlay failed and rollback is not proven: ${rollbackError.message}`,
        { cause: rollbackError, phase: "rollback-failed" },
      );
    }
  }
}

export async function executeOverlayTransaction({ approvedPlanSha256, ops, plan }) {
  validateOverlayPlan(plan);
  if (computeApprovedOverlayPlanSha256(plan) !== approvedPlanSha256) {
    fail("transaction plan does not match its externally approved SHA-256");
  }
  const release = await ops.acquireLock(plan.transaction.lock_path, {
    recoverStale: false,
    transactionId: plan.transaction_id,
  });
  return releasePreservingPrimary(release, () =>
    executeLocked({ approvedPlanSha256, ops, plan }));
}

function validateStateCommon(record, plan, approvedPlanSha256, phase) {
  if (
    record.schema_version !== 1 ||
    record.phase !== phase ||
    record.transaction_id !== plan.transaction_id ||
    record.approved_plan_sha256 !== approvedPlanSha256
  ) {
    fail(`durable transaction state ${phase} drifted from the approved plan`);
  }
}

function validateRecoveryCandidateSnapshot(snapshot, plan) {
  exactKeys(
    snapshot,
    ["ctime_ns", "device", "gid", "inode", "mode", "mtime_ns", "nlink", "path", "sha256", "size", "uid"],
    "prepared candidate snapshot",
  );
  if (
    snapshot.path !== plan.transaction.candidate_path ||
    snapshot.sha256 !== plan.managed_block.candidate_sha256 ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0644" ||
    snapshot.nlink !== 1
  ) {
    fail("prepared state candidate snapshot drifted");
  }
  for (const key of ["ctime_ns", "device", "inode", "mtime_ns", "size"]) {
    if (typeof snapshot[key] !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(snapshot[key])) {
      fail(`prepared state candidate snapshot ${key} is not a canonical decimal`);
    }
  }
  if (snapshot.inode === "0") fail("prepared state candidate snapshot inode must be positive");
}

function validationRollback() {
  return {
    attempted: true,
    directory_fsync: true,
    exact_candidate_swapped_out: true,
    exact_preimage_restored: true,
    exchanged: true,
    reload_exit_status: 0,
  };
}

function validateRecoveryReceiptComponents({
  after,
  approvedPlanSha256,
  context,
  installation,
  plan,
  reload,
  rollback,
}) {
  validateOverlayReceipt({
    approvedPlanSha256,
    plan,
    receipt: baseReceipt({
      after,
      approvedPlanSha256,
      backup: context.backup,
      before: context.before,
      healthResults: [],
      host: context.host,
      installation,
      outcome: "rolled-back",
      plan,
      preparation: context.preparation,
      reload,
      rollback,
    }),
  });
}

function loadRecoveryModel(records, plan, approvedPlanSha256) {
  const byPhase = new Map();
  for (const [filename, bytes] of records) {
    const phase = Object.entries(PHASE_TO_FILE).find((entry) => entry[1] === filename)?.[0];
    if (phase === undefined) fail(`unknown durable transaction state file ${filename}`);
    const record = parseStrictJson(Buffer.from(bytes).toString("utf8"), `state ${filename}`);
    validateStateCommon(record, plan, approvedPlanSha256, phase);
    byPhase.set(phase, record);
  }
  const prepared = byPhase.get("prepared");
  if (byPhase.size > 0 && prepared === undefined) fail("durable state is missing its prepared root record");
  const phaseExtraKeys = {
    "aborted-before-install": [],
    committed: ["receipt_sha256"],
    exchanged: ["installation"],
    prepared: ["candidate_snapshot", "context"],
    reloaded: ["reload"],
    "rollback-exchanged": [],
    "rollback-reloaded": ["after", "rollback"],
    "rolled-back": ["receipt_sha256"],
  };
  for (const [phase, record] of byPhase) {
    exactKeys(
      record,
      [
        "approved_plan_sha256",
        "phase",
        "previous_phase",
        "schema_version",
        "transaction_id",
        ...phaseExtraKeys[phase],
      ],
      `${phase} state`,
    );
  }
  if (prepared !== undefined) {
    if (prepared.previous_phase !== null) fail("prepared state has a predecessor");
    validateRecoveryCandidateSnapshot(prepared.candidate_snapshot, plan);
    exactKeys(
      prepared.context,
      ["backup", "before", "host", "preparation"],
      "prepared recovery context",
    );
    validateRecoveryReceiptComponents({
      after: prepared.context.before,
      approvedPlanSha256,
      context: prepared.context,
      installation: installationRecord(plan),
      plan,
      reload: {
        argv: structuredClone(plan.transaction.reload_argv),
        exit_status: 0,
        restart_invoked: false,
      },
      rollback: validationRollback(),
    });
  }
  const exchanged = byPhase.get("exchanged");
  if (exchanged !== undefined && !same(exchanged.installation, installationRecord(plan))) {
    fail("durable exchanged installation proof drifted");
  }
  const reloaded = byPhase.get("reloaded");
  if (reloaded !== undefined) {
    exactKeys(reloaded.reload, ["argv", "exit_status", "restart_invoked"], "reloaded state reload");
    if (
      !same(reloaded.reload.argv, plan.transaction.reload_argv) ||
      reloaded.reload.exit_status !== 0 ||
      reloaded.reload.restart_invoked !== false
    ) {
      fail("durable reloaded state drifted");
    }
  }
  const rollbackReloaded = byPhase.get("rollback-reloaded");
  if (rollbackReloaded !== undefined) {
    validateRecoveryReceiptComponents({
      after: rollbackReloaded.after,
      approvedPlanSha256,
      context: prepared.context,
      installation: exchanged?.installation ?? installationRecord(plan),
      plan,
      reload: reloaded?.reload ?? {
        argv: structuredClone(plan.transaction.reload_argv),
        exit_status: null,
        restart_invoked: false,
      },
      rollback: rollbackReloaded.rollback,
    });
  }
  for (const phase of ["committed", "rolled-back"]) {
    const terminal = byPhase.get(phase);
    if (
      terminal !== undefined &&
      (typeof terminal.receipt_sha256 !== "string" ||
        !/^[0-9a-f]{64}$/u.test(terminal.receipt_sha256))
    ) {
      fail(`durable ${phase} receipt digest is malformed`);
    }
  }
  const required = [
    ["exchanged", "prepared"],
    ["reloaded", "exchanged"],
    ["rollback-reloaded", "rollback-exchanged"],
    ["committed", "reloaded"],
    ["rolled-back", "rollback-reloaded"],
    ["aborted-before-install", "prepared"],
  ];
  for (const [phase, predecessor] of required) {
    const record = byPhase.get(phase);
    if (record !== undefined) {
      if (record.previous_phase !== predecessor) {
        fail(`durable ${phase} state has the wrong predecessor`);
      }
      if (!byPhase.has(predecessor)) {
        fail(`durable ${phase} state is missing predecessor ${predecessor}`);
      }
    }
  }
  const rollbackExchanged = byPhase.get("rollback-exchanged");
  if (
    rollbackExchanged !== undefined &&
    (!["exchanged", "reloaded"].includes(rollbackExchanged.previous_phase) ||
      !byPhase.has(rollbackExchanged.previous_phase))
  ) {
    fail("durable rollback-exchanged state has the wrong predecessor");
  }
  if (byPhase.has("committed") && (byPhase.has("rolled-back") || byPhase.has("rollback-exchanged"))) {
    fail("durable state contains contradictory terminal branches");
  }
  if (
    byPhase.has("aborted-before-install") &&
    [...byPhase.keys()].some((phase) => !["prepared", "aborted-before-install"].includes(phase))
  ) {
    fail("durable state contains both aborted and post-install branches");
  }
  return { byPhase, prepared };
}

async function classifyPair(plan, ops, candidateSnapshot) {
  const live = await ops.readRegular(TARGET_CONFIG);
  const candidate = await ops.readOptionalRegular(plan.transaction.candidate_path);
  const liveDigest = live.snapshot.sha256;
  const candidateDigest = candidate?.snapshot.sha256;
  if (
    liveDigest === plan.target.config_preimage.sha256 &&
    candidateDigest === plan.managed_block.candidate_sha256
  ) {
    assertExchangeIdentity(live.snapshot, plan.target.config_preimage, TARGET_CONFIG, "recovery live preimage");
    if (candidateSnapshot !== undefined) {
      assertExchangeIdentity(candidate.snapshot, candidateSnapshot, plan.transaction.candidate_path, "recovery candidate");
    }
    return { candidate, kind: "rolled-back", live };
  }
  if (
    liveDigest === plan.managed_block.candidate_sha256 &&
    candidateDigest === plan.target.config_preimage.sha256
  ) {
    if (candidateSnapshot !== undefined) {
      assertExchangeIdentity(live.snapshot, candidateSnapshot, TARGET_CONFIG, "recovery live candidate");
    } else {
      assertFinalConfig(live.snapshot, plan.managed_block.candidate_sha256, "recovery live candidate");
    }
    assertExchangeIdentity(candidate.snapshot, plan.target.config_preimage, plan.transaction.candidate_path, "recovery swapped preimage");
    return { candidate, kind: "installed", live };
  }
  if (liveDigest === plan.target.config_preimage.sha256 && candidate === null) {
    assertExchangeIdentity(live.snapshot, plan.target.config_preimage, TARGET_CONFIG, "recovery live preimage");
    return { candidate: null, kind: "preimage-only", live };
  }
  if (liveDigest === plan.managed_block.candidate_sha256 && candidate === null) {
    assertFinalConfig(live.snapshot, plan.managed_block.candidate_sha256, "recovery committed candidate");
    return { candidate: null, kind: "candidate-only", live };
  }
  fail("recovery found an unknown target/candidate digest combination; refusing to overwrite either entry");
}

function pendingReceiptShape(snapshot, plan) {
  if (
    snapshot.path !== plan.transaction.receipt_pending_path ||
    snapshot.uid !== 0 ||
    snapshot.gid !== 0 ||
    snapshot.mode !== "0400" ||
    snapshot.nlink !== 1
  ) {
    fail("pending receipt is not one root-owned owner-only transaction file");
  }
}

async function readAndValidateReceipt(ops, plan, approvedPlanSha256, pairKind) {
  let observed = await ops.readOptionalRegular(plan.transaction.receipt_path);
  const pending = await ops.readOptionalRegular(plan.transaction.receipt_pending_path);
  if (observed === null && pending !== null) {
    pendingReceiptShape(pending.snapshot, plan);
    let pendingReceipt;
    try {
      pendingReceipt = parseStrictJson(pending.bytes.toString("utf8"), "pending overlay receipt");
      validateOverlayReceipt({
        approvedPlanSha256,
        plan,
        receipt: pendingReceipt,
        trustedReceiptSha256: pending.snapshot.sha256,
      });
    } catch {
      // A crash can leave the exclusively-created pending entry before its
      // bytes or fsync complete. Its exact owner-only transaction name is not
      // authoritative until strict receipt validation succeeds.
      await ops.removeIfExact(plan.transaction.receipt_pending_path, pending.snapshot);
      return null;
    }
    const expectedPairs = pendingReceipt.outcome === "committed"
      ? ["installed", "candidate-only"]
      : ["rolled-back", "preimage-only"];
    if (!expectedPairs.includes(pairKind)) {
      fail("valid pending receipt contradicts the exact target/candidate file pair");
    }
    await ops.publishPendingReceipt(
      plan.transaction.receipt_pending_path,
      plan.transaction.receipt_path,
      plan.runtime.exchange_helper,
    );
    observed = await ops.readRegular(plan.transaction.receipt_path);
  } else if (observed !== null && pending !== null) {
    pendingReceiptShape(pending.snapshot, plan);
    if (!pending.bytes.equals(observed.bytes)) {
      fail("final and pending receipt entries disagree");
    }
    await ops.removeIfExact(plan.transaction.receipt_pending_path, pending.snapshot);
  }
  if (observed === null) return null;
  const receipt = parseStrictJson(observed.bytes.toString("utf8"), "durable overlay receipt");
  validateOverlayReceipt({
    approvedPlanSha256,
    plan,
    receipt,
    trustedReceiptSha256: observed.snapshot.sha256,
  });
  return { observed, receipt };
}

async function recoverLocked({ approvedPlanSha256, ops, plan }) {
  const records = await ops.readStateRecords(plan.transaction.state_directory);
  const model = loadRecoveryModel(records, plan, approvedPlanSha256);
  const candidateSnapshot = model.prepared?.candidate_snapshot;
  const pair = await classifyPair(plan, ops, candidateSnapshot);
  const durableReceipt = await readAndValidateReceipt(
    ops,
    plan,
    approvedPlanSha256,
    pair.kind,
  );
  if (durableReceipt !== null) {
    const expectedPair = durableReceipt.receipt.outcome === "committed"
      ? ["installed", "candidate-only"]
      : ["rolled-back", "preimage-only"];
    if (!expectedPair.includes(pair.kind)) {
      fail("durable receipt outcome contradicts the exact recovery file pair");
    }
    const terminalPhase = durableReceipt.receipt.outcome === "committed" ? "committed" : "rolled-back";
    const terminalRecord = model.byPhase.get(terminalPhase);
    if (
      terminalRecord !== undefined &&
      terminalRecord.receipt_sha256 !== durableReceipt.observed.snapshot.sha256
    ) {
      fail("terminal state receipt digest contradicts the durable receipt");
    }
    if (!model.byPhase.has(terminalPhase)) {
      await writeState(
        ops,
        plan,
        stateRecord(
          plan,
          approvedPlanSha256,
          terminalPhase,
          terminalPhase === "committed" ? "reloaded" : "rollback-reloaded",
          { receipt_sha256: durableReceipt.observed.snapshot.sha256 },
        ),
      );
    }
    if (pair.candidate !== null) {
      await ops.removeIfExact(
        plan.transaction.candidate_path,
        terminalPhase === "committed"
          ? { ...plan.target.config_preimage, path: plan.transaction.candidate_path }
          : candidateSnapshot,
      );
    }
    return durableReceipt.receipt;
  }
  if (model.byPhase.has("committed") || model.byPhase.has("rolled-back")) {
    fail("terminal state exists without its exact durable receipt");
  }
  if (pair.kind === "preimage-only") {
    if (model.byPhase.size === 0 || model.byPhase.has("aborted-before-install")) {
      return { outcome: "aborted-before-install", transaction_id: plan.transaction_id };
    }
    fail("recovery is missing the candidate required to prove an unfinished transaction");
  }
  if (pair.kind === "rolled-back" && !model.byPhase.has("exchanged")) {
    if (model.byPhase.size === 0) {
      await ops.removeIfExact(plan.transaction.candidate_path, pair.candidate.snapshot);
      return { outcome: "aborted-before-install", transaction_id: plan.transaction_id };
    }
    if (!model.byPhase.has("aborted-before-install")) {
      await writeState(
        ops,
        plan,
        stateRecord(plan, approvedPlanSha256, "aborted-before-install", "prepared"),
      );
    }
    await ops.removeIfExact(plan.transaction.candidate_path, candidateSnapshot);
    return { outcome: "aborted-before-install", transaction_id: plan.transaction_id };
  }
  if (pair.kind === "installed") {
    if (!model.byPhase.has("exchanged")) {
      const installation = installationRecord(plan);
      await writeState(
        ops,
        plan,
        stateRecord(plan, approvedPlanSha256, "exchanged", "prepared", { installation }),
      );
      model.byPhase.set("exchanged", { installation });
    }
    await exchangeInstalledPairForRollback(plan, ops, candidateSnapshot);
    if (!model.byPhase.has("rollback-exchanged")) {
      await writeState(
        ops,
        plan,
        stateRecord(
          plan,
          approvedPlanSha256,
          "rollback-exchanged",
          model.byPhase.has("reloaded") ? "reloaded" : "exchanged",
        ),
      );
      model.byPhase.set("rollback-exchanged", {});
    }
  } else if (pair.kind !== "rolled-back") {
    fail("recovery cannot prove a rollback-safe file pair");
  }
  if (pair.kind === "rolled-back" && !model.byPhase.has("rollback-exchanged")) {
    await writeState(
      ops,
      plan,
      stateRecord(
        plan,
        approvedPlanSha256,
        "rollback-exchanged",
        model.byPhase.has("reloaded") ? "reloaded" : "exchanged",
      ),
    );
    model.byPhase.set("rollback-exchanged", {});
  }
  const prepared = model.prepared;
  if (prepared === undefined) fail("rollback recovery lacks its durable prepared context");
  const exchangedRecord = model.byPhase.get("exchanged");
  const installation = exchangedRecord.installation ?? installationRecord(plan);
  const reloadedRecord = model.byPhase.get("reloaded");
  const reload = reloadedRecord?.reload ?? {
    argv: structuredClone(plan.transaction.reload_argv),
    exit_status: null,
    restart_invoked: false,
  };
  const rollbackReload = await ops.run(plan.transaction.reload_argv, {
    captureStdout: false,
    maxBytes: MAX_COMMAND_BYTES,
    timeoutMs: 30_000,
  });
  if (rollbackReload.status !== 0) fail("recovery rollback reload failed");
  const restoredState = await collectPinnedState(plan, ops, "recovery post-rollback", {
    requirePreimage: false,
  });
  const finalConfig = await ops.readRegular(TARGET_CONFIG);
  assertFinalConfig(finalConfig.snapshot, plan.target.config_preimage.sha256, "recovery restored Caddyfile");
  const rollback = {
    attempted: true,
    directory_fsync: true,
    exact_candidate_swapped_out: true,
    exact_preimage_restored: true,
    exchanged: true,
    reload_exit_status: rollbackReload.status,
  };
  const after = receiptSnapshot(plan, restoredState, finalConfig.snapshot);
  if (!model.byPhase.has("rollback-reloaded")) {
    await writeState(
      ops,
      plan,
      stateRecord(plan, approvedPlanSha256, "rollback-reloaded", "rollback-exchanged", {
        after,
        rollback,
      }),
    );
  }
  const context = prepared.context;
  const receipt = baseReceipt({
    after,
    approvedPlanSha256,
    backup: context.backup,
    before: context.before,
    healthResults: [],
    host: context.host,
    installation,
    outcome: "rolled-back",
    plan,
    preparation: context.preparation,
    reload,
    rollback,
  });
  const digest = await writeReceipt(ops, plan, approvedPlanSha256, receipt);
  await writeState(
    ops,
    plan,
    stateRecord(plan, approvedPlanSha256, "rolled-back", "rollback-reloaded", {
      receipt_sha256: digest,
    }),
  );
  await ops.removeIfExact(plan.transaction.candidate_path, candidateSnapshot);
  return receipt;
}

export async function recoverOverlayTransaction({ approvedPlanSha256, ops, plan }) {
  validateOverlayPlan(plan);
  if (computeApprovedOverlayPlanSha256(plan) !== approvedPlanSha256) {
    fail("recovery plan does not match its externally approved SHA-256");
  }
  const release = await ops.acquireLock(plan.transaction.lock_path, {
    recoverStale: true,
    transactionId: plan.transaction_id,
  });
  return releasePreservingPrimary(release, () =>
    recoverLocked({ approvedPlanSha256, ops, plan }));
}

function modeString(stat) {
  return (Number(stat.mode & 0o7777n)).toString(8).padStart(4, "0");
}

function snapshotFromStat(path, stat, bytes) {
  return {
    ctime_ns: stat.ctimeNs.toString(),
    device: stat.dev.toString(),
    gid: Number(stat.gid),
    inode: stat.ino.toString(),
    mode: modeString(stat),
    mtime_ns: stat.mtimeNs.toString(),
    nlink: Number(stat.nlink),
    path,
    sha256: sha256(bytes),
    size: stat.size.toString(),
    uid: Number(stat.uid),
  };
}

function canonicalAbsolute(path) {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("//") || path.includes("\0")) {
    fail(`path is not one canonical absolute path: ${path}`);
  }
  return path;
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function openSealedParent(path) {
  canonicalAbsolute(path);
  const components = dirname(path).split("/").filter(Boolean);
  const descriptors = [];
  let fd;
  try {
    fd = openSync(
      "/",
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    descriptors.push({ fd, path: "/", stat: null });
    descriptors.at(-1).stat = fstatSync(fd, { bigint: true });
    let currentPath = "";
    for (const component of components) {
      currentPath += `/${component}`;
      const next = openSync(
        `/proc/self/fd/${fd}/${component}`,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
      );
      descriptors.push({ fd: next, path: currentPath, stat: null });
      const descriptorStat = fstatSync(next, { bigint: true });
      descriptors.at(-1).stat = descriptorStat;
      const pathStat = lstatSync(currentPath, { bigint: true, throwIfNoEntry: true });
      if (!descriptorStat.isDirectory() || !pathStat.isDirectory() || !sameInode(descriptorStat, pathStat)) {
        fail(`directory parent changed or became a symlink: ${currentPath}`);
      }
      fd = next;
    }
  } catch (error) {
    for (const descriptor of descriptors.reverse()) {
      try {
        closeSync(descriptor.fd);
      } catch {
        // Preserve the traversal failure; no descriptor remains usable here.
      }
    }
    throw error;
  }
  let closed = false;
  return {
    close() {
      if (closed) return;
      closed = true;
      for (const descriptor of [...descriptors].reverse()) closeSync(descriptor.fd);
    },
    confirm() {
      for (const descriptor of descriptors) {
        const current = lstatSync(descriptor.path, { bigint: true, throwIfNoEntry: true });
        if (!current.isDirectory() || !sameInode(current, descriptor.stat)) {
          fail(`directory parent drifted during descriptor operation: ${descriptor.path}`);
        }
      }
    },
    fd,
    procPath: `/proc/self/fd/${fd}/${basename(path)}`,
  };
}

function realReadRegular(path, maxBytes = MAX_FILE_BYTES) {
  const parent = openSealedParent(path);
  let fd;
  try {
    fd = openSync(
      parent.procPath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
    );
    const stat = fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(maxBytes)) {
      fail(`regular-file boundary failed for ${path}`);
    }
    const bytes = readFileSync(fd);
    if (bytes.length > maxBytes) fail(`regular file exceeded its bounded read: ${path}`);
    const confirmation = fstatSync(fd, { bigint: true });
    if (
      !sameInode(confirmation, stat) ||
      confirmation.size !== stat.size ||
      confirmation.ctimeNs !== stat.ctimeNs ||
      confirmation.mtimeNs !== stat.mtimeNs
    ) {
      fail(`regular file changed during descriptor read: ${path}`);
    }
    const pathStat = lstatSync(path, { bigint: true, throwIfNoEntry: true });
    if (!pathStat.isFile() || !sameInode(pathStat, stat)) {
      fail(`regular file path changed or became a symlink during descriptor read: ${path}`);
    }
    parent.confirm();
    return { bytes, snapshot: snapshotFromStat(path, stat, bytes) };
  } finally {
    if (fd !== undefined) closeSync(fd);
    parent.close();
  }
}

function realReadOptionalRegular(path) {
  try {
    return realReadRegular(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function realReadDirectory(path) {
  const parent = openSealedParent(`${path}/.directory-pin`);
  try {
    const stat = fstatSync(parent.fd, { bigint: true });
    parent.confirm();
    return {
      device: stat.dev.toString(),
      gid: Number(stat.gid),
      inode: stat.ino.toString(),
      mode: modeString(stat),
      path,
      uid: Number(stat.uid),
    };
  } finally {
    parent.close();
  }
}

function fsyncParent(path) {
  const parent = openSealedParent(path);
  try {
    fsyncSync(parent.fd);
    parent.confirm();
  } finally {
    parent.close();
  }
}

function realWriteExclusive(path, bytes, mode) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_FILE_BYTES) {
    fail(`exclusive write is not one bounded byte buffer: ${path}`);
  }
  const parent = openSealedParent(path);
  const numericMode = Number.parseInt(mode, 8);
  let fd;
  try {
    fd = openSync(
      parent.procPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW |
        constants.O_CLOEXEC,
      numericMode,
    );
    fchmodSync(fd, numericMode);
    fchownSync(fd, 0, 0);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    parent.confirm();
    fsyncSync(parent.fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
    parent.close();
  }
  const observed = realReadRegular(path);
  return {
    directoryFsync: true,
    exclusiveCreate: true,
    fileFsync: true,
    snapshot: observed.snapshot,
  };
}

function commandResult(argv, { captureStdout, maxBytes, timeoutMs, extraFd } = {}) {
  const stdio = ["ignore", captureStdout ? "pipe" : "ignore", "pipe"];
  if (extraFd !== undefined) stdio.push(extraFd);
  const result = spawnSync(argv[0], argv.slice(1), {
    encoding: null,
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    killSignal: "SIGKILL",
    maxBuffer: maxBytes,
    shell: false,
    stdio,
    timeout: timeoutMs,
  });
  return {
    status: result.status ?? 255,
    stderr: result.stderr ?? Buffer.alloc(0),
    stdout: result.stdout ?? Buffer.alloc(0),
  };
}

function unitGeneration(unitName) {
  const properties = [
    "ActiveEnterTimestampMonotonic",
    "ActiveState",
    "CanReload",
    "ControlGroup",
    "InvocationID",
    "MainPID",
    "SubState",
  ];
  const result = commandResult(
    [
      "/usr/bin/systemctl",
      "show",
      unitName,
      "--no-pager",
      ...properties.map((property) => `--property=${property}`),
    ],
    { captureStdout: true, maxBytes: 64 * 1024, timeoutMs: 10_000 },
  );
  if (result.status !== 0) fail(`systemctl show failed for ${unitName}`);
  const values = new Map();
  for (const line of result.stdout.toString("utf8").trimEnd().split("\n")) {
    const separator = line.indexOf("=");
    if (separator < 1) fail(`malformed systemctl show output for ${unitName}`);
    const key = line.slice(0, separator);
    if (values.has(key)) fail(`duplicate systemctl property ${key}`);
    values.set(key, line.slice(separator + 1));
  }
  if (values.size !== properties.length || properties.some((key) => !values.has(key))) {
    fail(`systemctl show omitted a property for ${unitName}`);
  }
  return {
    active_enter_timestamp_monotonic: values.get("ActiveEnterTimestampMonotonic"),
    active_state: values.get("ActiveState"),
    can_reload: values.get("CanReload"),
    control_group: values.get("ControlGroup"),
    invocation_id: values.get("InvocationID"),
    main_pid: values.get("MainPID"),
    sub_state: values.get("SubState"),
    unit_name: unitName,
  };
}

function runtimePath(path) {
  const stat = lstatSync(path, { bigint: true });
  return {
    file_type: stat.isDirectory() ? "directory" : stat.isSocket() ? "socket" : "other",
    gid: Number(stat.gid),
    mode: modeString(stat),
    path,
    uid: Number(stat.uid),
  };
}

function parseHeaders(headerBytes, lane) {
  const lines = headerBytes.toString("ascii").split("\r\n");
  const match = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/u.exec(lines.shift() ?? "");
  if (!match) fail(`malformed health response status for ${lane}`);
  const headers = new Map();
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator < 1) fail(`malformed health response header for ${lane}`);
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (headers.has(name)) fail(`duplicate health response header ${name} for ${lane}`);
    headers.set(name, value);
  }
  return { headers, status: Number(match[1]) };
}

export function verifyWebSocketUpgrade({
  expectedStatus,
  headerBytes,
  key,
  lane = "websocket-health",
}) {
  const { headers, status } = parseHeaders(Buffer.from(headerBytes), lane);
  const expectedAccept = createHash("sha1")
    .update(`${key}${WS_GUID}`)
    .digest("base64");
  if (
    status !== expectedStatus ||
    headers.get("upgrade")?.toLowerCase() !== "websocket" ||
    !(headers.get("connection") ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .includes("upgrade") ||
    headers.get("sec-websocket-accept") !== expectedAccept
  ) {
    fail(`WebSocket upgrade proof failed for ${lane}`);
  }
  return status;
}

function decodeChunked(bytes, lane) {
  const chunks = [];
  let offset = 0;
  while (true) {
    const end = bytes.indexOf("\r\n", offset);
    if (end < 0) fail(`truncated chunk header for ${lane}`);
    const line = bytes.subarray(offset, end).toString("ascii");
    if (!/^[0-9A-Fa-f]+$/u.test(line)) fail(`invalid chunk length for ${lane}`);
    const length = Number.parseInt(line, 16);
    offset = end + 2;
    if (length === 0) {
      if (!bytes.subarray(offset).equals(Buffer.from("\r\n"))) {
        fail(`health response trailers are not accepted for ${lane}`);
      }
      return Buffer.concat(chunks);
    }
    if (offset + length + 2 > bytes.length) fail(`truncated chunk body for ${lane}`);
    chunks.push(bytes.subarray(offset, offset + length));
    offset += length;
    if (!bytes.subarray(offset, offset + 2).equals(Buffer.from("\r\n"))) {
      fail(`malformed chunk terminator for ${lane}`);
    }
    offset += 2;
  }
}

function responseBody(response, headerEnd, headers, lane) {
  let body = response.subarray(headerEnd + 4);
  const transferEncoding = headers.get("transfer-encoding")?.toLowerCase();
  const contentLength = headers.get("content-length");
  if (transferEncoding !== undefined && contentLength !== undefined) {
    fail(`ambiguous health response framing for ${lane}`);
  }
  if (transferEncoding !== undefined) {
    if (transferEncoding !== "chunked") fail(`unsupported health transfer encoding for ${lane}`);
    body = decodeChunked(body, lane);
  } else if (contentLength !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) fail(`invalid health content-length for ${lane}`);
    if (body.length !== Number(contentLength)) fail(`health content-length mismatch for ${lane}`);
  }
  return body;
}

export function healthCheck(check) {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let response = Buffer.alloc(0);
    let leafCertificateSha256;
    let websocketKey;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) rejectPromise(error);
      else resolvePromise(value);
    };
    const socket = tls.connect({
      host: check.connect_ip,
      minVersion: "TLSv1.2",
      port: 443,
      rejectUnauthorized: true,
      servername: check.host,
    });
    const timer = setTimeout(
      () => finish(new Error(`health timeout for ${check.lane}`)),
      check.timeout_ms,
    );
    socket.once("secureConnect", () => {
      if (!socket.authorized) {
        finish(new Error(`health TLS chain or hostname rejected for ${check.lane}`));
        return;
      }
      const certificate = socket.getPeerCertificate(true);
      if (!certificate?.raw) {
        finish(new Error(`health TLS certificate missing for ${check.lane}`));
        return;
      }
      leafCertificateSha256 = sha256(certificate.raw);
      if (leafCertificateSha256 !== check.leaf_certificate_sha256) {
        finish(new Error(`health TLS certificate drift for ${check.lane}`));
        return;
      }
      const websocket = check.kind === "websocket-upgrade";
      if (websocket) websocketKey = randomBytes(16).toString("base64");
      socket.write([
        `GET ${check.path} HTTP/1.1`,
        `Host: ${check.host}`,
        websocket ? "Connection: Upgrade" : "Connection: close",
        ...(websocket
          ? [
              "Upgrade: websocket",
              "Sec-WebSocket-Version: 13",
              `Sec-WebSocket-Key: ${websocketKey}`,
            ]
          : []),
        "User-Agent: bitcoinpir-overlay-health-v1",
        "",
        "",
      ].join("\r\n"));
    });
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > check.max_response_bytes) {
        finish(new Error(`health response too large for ${check.lane}`));
        return;
      }
      const headerEnd = response.indexOf("\r\n\r\n");
      if (headerEnd < 0 || check.kind !== "websocket-upgrade") return;
      try {
        const status = verifyWebSocketUpgrade({
          expectedStatus: check.expected_status,
          headerBytes: response.subarray(0, headerEnd),
          key: websocketKey,
          lane: check.lane,
        });
        finish(null, {
          body_sha256: null,
          leaf_certificate_sha256: leafCertificateSha256,
          status,
          success: true,
        });
      } catch (error) {
        finish(error);
      }
    });
    socket.once("end", () => {
      if (check.kind === "websocket-upgrade") return;
      try {
        const headerEnd = response.indexOf("\r\n\r\n");
        if (headerEnd < 0) fail(`truncated health response for ${check.lane}`);
        const { headers, status } = parseHeaders(response.subarray(0, headerEnd), check.lane);
        const body = responseBody(response, headerEnd, headers, check.lane);
        const bodySha256 = sha256(body);
        finish(null, {
          body_sha256: bodySha256,
          leaf_certificate_sha256: leafCertificateSha256,
          status,
          success: status === check.expected_status && bodySha256 === check.expected_body_sha256,
        });
      } catch (error) {
        finish(error);
      }
    });
    socket.once("error", (error) => finish(error));
  });
}

function processStartTicks(pid) {
  const text = readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = text.lastIndexOf(")");
  if (close < 1) fail(`malformed /proc/${pid}/stat`);
  const fields = text.slice(close + 2).trim().split(/\s+/u);
  const start = fields[19];
  if (!/^[1-9][0-9]*$/u.test(start ?? "")) fail(`missing process starttime for PID ${pid}`);
  return start;
}

function bootId() {
  const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  if (!/^[0-9a-f-]{36}$/u.test(value)) fail("kernel boot_id is malformed");
  return value;
}

function lockOwner(transactionId) {
  return {
    boot_id: bootId(),
    pid: process.pid,
    process_start_ticks: processStartTicks(process.pid),
    transaction_id: transactionId,
  };
}

function ownerIsLive(owner) {
  exactKeys(owner, ["boot_id", "pid", "process_start_ticks", "transaction_id"], "lock owner");
  if (owner.boot_id !== bootId()) return false;
  if (!Number.isSafeInteger(owner.pid) || owner.pid < 1) fail("lock owner PID is malformed");
  try {
    return processStartTicks(owner.pid) === owner.process_start_ticks;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

export function acquireFilesystemLock(path, { recoverStale, transactionId }) {
  const create = () => {
    mkdirSync(path, { mode: 0o700 });
    fsyncParent(path);
    const owner = lockOwner(transactionId);
    const ownerBytes = Buffer.from(canonicalJson(owner), "utf8");
    realWriteExclusive(`${path}/${LOCK_OWNER}`, ownerBytes, "0400");
    return { owner, ownerBytes };
  };
  let held;
  try {
    held = create();
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    if (!recoverStale) fail("transaction lock already exists; use the explicit recover command");
    const entries = readdirSync(path, { withFileTypes: true });
    if (entries.length === 0) {
      rmdirSync(path);
      fsyncParent(path);
      held = create();
    } else {
      if (entries.length !== 1 || entries[0].name !== LOCK_OWNER || !entries[0].isFile()) {
        fail("stale lock directory has an unknown shape; refusing to guess ownership");
      }
      const existing = realReadRegular(`${path}/${LOCK_OWNER}`, 64 * 1024);
      const owner = parseStrictJson(existing.bytes.toString("utf8"), "lock owner");
      if (ownerIsLive(owner)) fail("transaction lock is held by a live process generation");
      unlinkSync(`${path}/${LOCK_OWNER}`);
      rmdirSync(path);
      fsyncParent(path);
      held = create();
    }
  }
  return async () => {
    const observed = realReadRegular(`${path}/${LOCK_OWNER}`, 64 * 1024);
    if (!observed.bytes.equals(held.ownerBytes)) fail("transaction lock ownership changed before release");
    const entries = readdirSync(path, { withFileTypes: true });
    if (entries.length !== 1 || entries[0].name !== LOCK_OWNER || !entries[0].isFile()) {
      fail("transaction lock directory changed before release");
    }
    unlinkSync(`${path}/${LOCK_OWNER}`);
    rmdirSync(path);
    fsyncParent(path);
  };
}

function invokePinnedHelper(action, left, right, helperPin) {
  if (!["--exchange", "--publish"].includes(action)) fail("unreviewed rename helper action");
  const helper = realReadRegular(helperPin.path);
  exactRegularSnapshot(helper.snapshot, helperPin, "rename-exchange helper before invocation");
  const fd = openSync(
    helperPin.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
  );
  try {
    const stat = fstatSync(fd, { bigint: true });
    if (stat.dev.toString() !== helperPin.device || stat.ino.toString() !== helperPin.inode) {
      fail("rename-exchange helper path raced after verification");
    }
    const result = commandResult(
      ["/proc/self/fd/3", action, left, right],
      {
        captureStdout: false,
        extraFd: fd,
        maxBytes: 64 * 1024,
        timeoutMs: 10_000,
      },
    );
    if (result.status !== 0) {
      fail(`renameat2 helper ${action} failed: ${result.stderr.toString("utf8").trim()}`);
    }
  } finally {
    closeSync(fd);
  }
  fsyncParent(left);
}

export function linuxOverlayOps() {
  if (process.platform !== "linux") fail("integrated Caddy transaction requires Linux");
  if (typeof process.geteuid !== "function" || process.geteuid() !== 0) {
    fail("integrated Caddy transaction requires effective UID 0");
  }
  return {
    async acquireLock(path, options) {
      return acquireFilesystemLock(path, options);
    },
    async exchange(left, right, helperPin) {
      if (dirname(left) !== dirname(right)) fail("exchange entries must share one exact parent");
      invokePinnedHelper("--exchange", left, right, helperPin);
    },
    async health(check) {
      return healthCheck(check);
    },
    async hostIdentity() {
      return {
        boot_id: bootId(),
        machine_id_sha256: sha256(readFileSync("/etc/machine-id")),
      };
    },
    async initializeStateDirectory(path) {
      mkdirSync(path, { mode: 0o700 });
      fsyncParent(path);
      const observed = realReadDirectory(path);
      if (observed.uid !== 0 || observed.gid !== 0 || observed.mode !== "0700") {
        fail("transaction state directory is not root:root mode 0700");
      }
    },
    async readDirectory(path) {
      return realReadDirectory(path);
    },
    async readOptionalRegular(path) {
      return realReadOptionalRegular(path);
    },
    async readRegular(path) {
      return realReadRegular(path);
    },
    async readRuntimePath(path) {
      return runtimePath(path);
    },
    async readStateRecords(path) {
      const allowed = new Set(Object.values(OVERLAY_STATE_FILES));
      const entries = readdirSync(path, { withFileTypes: true });
      const records = new Map();
      for (const entry of entries) {
        if (!entry.isFile() || !allowed.has(entry.name)) {
          fail(`unknown entry in durable transaction state: ${entry.name}`);
        }
        records.set(entry.name, realReadRegular(`${path}/${entry.name}`).bytes);
      }
      return records;
    },
    async readUnitGeneration(unitName) {
      return unitGeneration(unitName);
    },
    async removeIfExact(path, expectedSnapshot) {
      const observed = realReadOptionalRegular(path);
      if (observed === null) return;
      assertExchangeIdentity(observed.snapshot, expectedSnapshot, path, "temporary cleanup entry");
      unlinkSync(path);
      fsyncParent(path);
    },
    async run(argv, options) {
      return commandResult(argv, options);
    },
    async writeExclusive(path, bytes, mode) {
      return realWriteExclusive(path, bytes, mode);
    },
    async publishPendingReceipt(pendingPath, finalPath, helperPin) {
      if (dirname(pendingPath) !== dirname(finalPath)) {
        fail("pending and final receipt entries must share one exact parent");
      }
      invokePinnedHelper("--publish", pendingPath, finalPath, helperPin);
    },
    async writeReceipt(pendingPath, finalPath, bytes, helperPin) {
      const pending = realWriteExclusive(pendingPath, bytes, "0400");
      try {
        invokePinnedHelper("--publish", pendingPath, finalPath, helperPin);
      } catch (error) {
        if (realReadOptionalRegular(finalPath) === null) {
          const stillPending = realReadOptionalRegular(pendingPath);
          if (stillPending !== null) {
            assertExchangeIdentity(
              stillPending.snapshot,
              pending.snapshot,
              pendingPath,
              "failed receipt publication cleanup",
            );
            unlinkSync(pendingPath);
            fsyncParent(pendingPath);
          }
        }
        throw error;
      }
      const published = realReadRegular(finalPath);
      if (!published.bytes.equals(bytes)) fail("published receipt bytes drifted");
      return published;
    },
    async writeState(directory, filename, bytes) {
      return realWriteExclusive(`${directory}/${filename}`, bytes, "0400");
    },
  };
}

function parseArgs(argv) {
  const args = [...argv];
  const command = args[0]?.startsWith("--") ? "execute" : (args.shift() ?? "execute");
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined || options.has(key)) {
      fail("transaction arguments must be unique --name value pairs");
    }
    options.set(key, value);
  }
  return { command, options };
}

function requiredOption(options, name) {
  const value = options.get(name);
  if (value === undefined) fail(`missing required ${name}`);
  return value;
}

async function main(argv) {
  if (process.platform !== "linux") fail("integrated Caddy transaction requires Linux");
  const { command, options } = parseArgs(argv);
  const planPath = resolve(requiredOption(options, "--plan"));
  const plan = parseStrictJson(realReadRegular(planPath).bytes.toString("utf8"), "overlay plan");
  const approvedPlanSha256 = requiredOption(options, "--approved-plan-sha256");
  validateOverlayPlan(plan);
  if (
    plan.runtime.exchange_helper.path !== RENAME_EXCHANGE_HELPER ||
    plan.runtime.exchange_manifest.path !== RENAME_EXCHANGE_MANIFEST
  ) {
    fail("rendered executor helper dependencies do not match the exact overlay plan pins");
  }
  if (fileURLToPath(import.meta.url) !== plan.runtime.executor.path) {
    fail("transaction executor was not invoked from the exact plan-pinned path");
  }
  if (process.execPath !== plan.runtime.node_binary.path) {
    fail("transaction executor is not running under the exact plan-pinned Node path");
  }
  const ops = linuxOverlayOps();
  const result = command === "execute"
    ? await executeOverlayTransaction({ approvedPlanSha256, ops, plan })
    : command === "recover"
      ? await recoverOverlayTransaction({ approvedPlanSha256, ops, plan })
      : fail("usage: overlay-transaction.mjs execute|recover --plan ... --approved-plan-sha256 ...");
  if (result?.schema_version === 1) {
    process.stdout.write(
      `${result.outcome} receipt=${plan.transaction.receipt_path} sha256=${receiptDigest(result)}\n`,
    );
  } else {
    process.stdout.write(`${canonicalJson(result)}`);
  }
}

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    if (error?.receipt !== undefined) {
      process.stderr.write(`receipt=${error.receipt.transaction_id}\n`);
    }
    if (error?.lockReleaseError !== undefined) {
      process.stderr.write(`lock_release_error=${error.lockReleaseError.message}\n`);
    }
    process.exitCode = 1;
  });
}
