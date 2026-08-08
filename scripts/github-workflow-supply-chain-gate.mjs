#!/usr/bin/env node

import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const APPROVED_ACTION_COMMITS = Object.freeze({
  "actions/cache": "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
  "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/configure-pages": "45bfe0192ca1faeb007ade9deae92b16b8254a0d",
  "actions/deploy-pages": "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128",
  "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
  "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "actions/upload-pages-artifact": "fc324d3547104276b827a68afc52ff2a11cc49c9",
  "mozilla-actions/sccache-action": "fc920bf0ec8de6ee65d409111f7ec508035751ba",
});

export const SUPPLY_CHAIN_GATE_PUSH_PATHS = Object.freeze([
  ".github/workflows/**",
  "scripts/github-workflow-supply-chain-gate.mjs",
  "scripts/github-workflow-supply-chain-gate.test.mjs",
  "web/package.json",
  "web/package-lock.json",
  "web/npm-shrinkwrap.json",
]);

function fail(message) {
  throw new Error(`github-workflow-supply-chain-gate: ${message}`);
}

function requireCanonicalDirectory(path, label) {
  const absolute = resolve(path);
  const stat = lstatSync(absolute);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(absolute) !== absolute) {
    fail(`${label} must be one canonical non-symlink directory`);
  }
  return absolute;
}

export function validateNpmParserLockBoundary(repositoryRootInput) {
  const repositoryRoot = requireCanonicalDirectory(repositoryRootInput, "repository root");
  const shrinkwrapPath = resolve(repositoryRoot, "web/npm-shrinkwrap.json");
  if (lstatSync(shrinkwrapPath, { throwIfNoEntry: false }) !== undefined) {
    fail(
      "web/npm-shrinkwrap.json is forbidden because npm gives it precedence over web/package-lock.json",
    );
  }
}

// This check intentionally runs before loading the YAML package. A malicious
// higher-priority shrinkwrap must not get a chance to choose the parser module
// that evaluates the workflows or the parser's own negative tests.
validateNpmParserLockBoundary(REPOSITORY_ROOT);

let parseDocument;
let visit;
try {
  const requireFromWeb = createRequire(resolve(REPOSITORY_ROOT, "web/package.json"));
  ({ parseDocument, visit } = requireFromWeb("yaml"));
} catch {
  fail("locked YAML parser unavailable; run npm ci in web first");
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseWorkflowSource(source, label) {
  if (typeof source !== "string" || Buffer.byteLength(source, "utf8") > 2 * 1024 * 1024) {
    fail(`${label} must be bounded UTF-8 workflow text`);
  }
  const document = parseDocument(source, {
    maxAliasCount: 0,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });
  if (document.errors.length !== 0 || document.warnings.length !== 0) {
    fail(`${label} is not strict warning-free YAML`);
  }
  visit(document, {
    Alias() {
      fail(`${label} must not contain YAML aliases`);
    },
    Node(_key, node) {
      if (node?.anchor !== undefined) fail(`${label} must not contain YAML anchors`);
    },
    Pair(_key, pair) {
      if (pair?.key?.value === "<<") fail(`${label} must not contain YAML merge keys`);
    },
  });
  const workflow = document.toJS({ maxAliasCount: 0 });
  if (!isRecord(workflow)) fail(`${label} root must be a mapping`);
  return workflow;
}

function requireExactMappingKeys(value, expectedKeys, label) {
  if (!isRecord(value)) fail(`${label} must be a mapping`);
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpectedKeys.length ||
    actualKeys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    fail(`${label} must contain exactly: ${sortedExpectedKeys.join(", ")}`);
  }
}

function requireExactStringList(value, expectedValues, label) {
  if (
    !Array.isArray(value) ||
    value.length !== expectedValues.length ||
    value.some((entry, index) => entry !== expectedValues[index])
  ) {
    fail(`${label} must match the reviewed ordered list`);
  }
}

export function validateSupplyChainGateTriggers(source, label = "workflow supply-chain gate") {
  const workflow = parseWorkflowSource(source, label);
  requireExactMappingKeys(
    workflow.on,
    ["push", "pull_request", "merge_group", "workflow_dispatch"],
    `${label}.on`,
  );

  requireExactMappingKeys(workflow.on.push, ["branches", "paths"], `${label}.on.push`);
  requireExactStringList(workflow.on.push.branches, ["main"], `${label}.on.push.branches`);
  requireExactStringList(
    workflow.on.push.paths,
    SUPPLY_CHAIN_GATE_PUSH_PATHS,
    `${label}.on.push.paths`,
  );

  // A workflow-level PR path filter leaves a required check Pending on
  // unrelated PRs. Only the protected target branch may narrow this event.
  requireExactMappingKeys(
    workflow.on.pull_request,
    ["branches"],
    `${label}.on.pull_request`,
  );
  requireExactStringList(
    workflow.on.pull_request.branches,
    ["main"],
    `${label}.on.pull_request.branches`,
  );

  requireExactMappingKeys(
    workflow.on.merge_group,
    ["types"],
    `${label}.on.merge_group`,
  );
  requireExactStringList(
    workflow.on.merge_group.types,
    ["checks_requested"],
    `${label}.on.merge_group.types`,
  );
  if (workflow.on.workflow_dispatch !== null) {
    fail(`${label}.on.workflow_dispatch must be an input-free manual trigger`);
  }

  return { events: 4, pushPaths: SUPPLY_CHAIN_GATE_PUSH_PATHS.length };
}

function validateActionUse(actionUse, step, label) {
  if (typeof actionUse !== "string") fail(`${label}.uses must be a string`);
  const match = /^([0-9A-Za-z_.-]+\/[0-9A-Za-z_.-]+(?:\/[0-9A-Za-z_./-]+)?)@([0-9a-f]{40})$/u.exec(actionUse);
  if (!match) fail(`${label}.uses must pin one approved action to a lowercase 40-hex commit`);
  const action = match[1];
  const approvedCommit = APPROVED_ACTION_COMMITS[action];
  if (approvedCommit === undefined || match[2] !== approvedCommit) {
    fail(`${label}.uses is outside the reviewed action/commit allowlist: ${actionUse}`);
  }
  if (action === "actions/checkout") {
    if (!isRecord(step.with) || step.with["persist-credentials"] !== false) {
      fail(`${label} checkout must set persist-credentials: false as a YAML boolean`);
    }
  }
}

function walkWorkflow(value, label, counters) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walkWorkflow(entry, `${label}[${index}]`, counters));
    return;
  }
  if (!isRecord(value)) return;
  if (Object.hasOwn(value, "uses")) {
    validateActionUse(value.uses, value, label);
    counters.actionUses += 1;
    if (value.uses.startsWith("actions/checkout@")) counters.checkouts += 1;
  }
  for (const [key, child] of Object.entries(value)) {
    walkWorkflow(child, `${label}.${key}`, counters);
  }
}

export function validateWorkflowSource(source, label = "workflow") {
  const workflow = parseWorkflowSource(source, label);
  const counters = { actionUses: 0, checkouts: 0 };
  walkWorkflow(workflow, label, counters);
  if (counters.actionUses < 1 || counters.checkouts < 1) {
    fail(`${label} must contain at least one approved action and checkout`);
  }
  return counters;
}

function requireWorkflowStep(steps, predicate, label) {
  const step = steps.find((candidate) => isRecord(candidate) && predicate(candidate));
  if (step === undefined) fail(label);
  return step;
}

function normalizeWorkflowCommand(command) {
  return command.replaceAll(/\\\s*/gu, " ").replaceAll(/\s+/gu, " ").trim();
}

export function validatePaymentPlatformCompileAcceleration(
  source,
  label = "payment platform workflow",
) {
  const workflow = parseWorkflowSource(source, label);
  if (!isRecord(workflow.jobs) || !isRecord(workflow.jobs["protocol-and-persistence"])) {
    fail(`${label} must define the protocol-and-persistence job`);
  }
  const job = workflow.jobs["protocol-and-persistence"];
  if (!isRecord(job.env)) fail(`${label} protocol job must define compiler-cache env`);
  const expectedEnv = {
    CARGO_PROFILE_TEST_LTO: "off",
    CARGO_INCREMENTAL: "0",
    SCCACHE_GHA_ENABLED: "true",
    RUSTC_WRAPPER: "sccache",
  };
  for (const [key, value] of Object.entries(expectedEnv)) {
    if (job.env[key] !== value) fail(`${label} protocol job must set ${key}=${value}`);
  }
  if (!Array.isArray(job.steps)) fail(`${label} protocol job steps must be a list`);

  const steps = job.steps;
  const sccacheAction = `mozilla-actions/sccache-action@${APPROVED_ACTION_COMMITS["mozilla-actions/sccache-action"]}`;
  requireWorkflowStep(
    steps,
    (step) => step.uses === sccacheAction,
    `${label} protocol job must install the reviewed sccache action`,
  );
  if (steps.some((step) => typeof step.uses === "string" && step.uses.startsWith("actions/cache@"))) {
    fail(`${label} protocol job must not cache the workspace target directory`);
  }

  const cargoRuns = steps
    .filter((step) => typeof step.run === "string")
    .map((step) => step.run)
    .join("\n");
  for (const command of ["cargo test --timings", "cargo clippy --timings", "cargo build --timings"]) {
    if (!cargoRuns.includes(command)) {
      fail(`${label} protocol job must collect timings from a representative ${command}`);
    }
  }
  const stats = requireWorkflowStep(
    steps,
    (step) => step.if === "always()" && typeof step.run === "string" &&
      step.run.includes("SCCACHE_PATH") && step.run.includes("--show-stats"),
    `${label} protocol job must report sccache stats in an always step`,
  );
  if (stats.shell !== "bash") fail(`${label} sccache stats step must use bash`);
  const timingArtifact = requireWorkflowStep(
    steps,
    (step) => step.if === "always()" &&
      step.uses === `actions/upload-artifact@${APPROVED_ACTION_COMMITS["actions/upload-artifact"]}` &&
      isRecord(step.with) && typeof step.with.path === "string",
    `${label} protocol job must upload only Cargo timing reports`,
  );
  requireExactStringList(
    timingArtifact.with.path.trimEnd().split("\n").map((path) => path.trim()),
    ["target/cargo-timings", "target/payment-issuer-shared-e2e/cargo-timings"],
    `${label} Cargo timing artifact paths`,
  );
  if (timingArtifact.with["if-no-files-found"] !== "ignore" || timingArtifact.with["retention-days"] !== 7) {
    fail(`${label} Cargo timing artifact must be optional with seven-day retention`);
  }

  const featureSupersetStep = requireWorkflowStep(
    steps,
    (step) => step.name === "Lint runtime ORAM, Standard Cashu, and shared-issuer feature superset" &&
      typeof step.run === "string",
    `${label} protocol job must lint the reviewed runtime feature superset`,
  );
  const featureSupersetCommand = normalizeWorkflowCommand(featureSupersetStep.run);
  for (const requiredArgument of [
    "cargo clippy --locked --offline -p runtime",
    "--features cuckoo-oram,shared-issuer-process-e2e",
    "--bin unified_server",
    "--test payment_v1_tee_oram_process_e2e",
    "--test payment_v1_standard_cashu_process_e2e",
    "--test payment_v1_process_e2e",
    "--test payment_v1_harmony_pool_process_e2e",
    "--test payment_v1_onion_process_e2e",
    "--test payment_v1_shared_issuer_process_e2e",
    "--no-deps -- -D warnings",
  ]) {
    if (!featureSupersetCommand.includes(requiredArgument)) {
      fail(`${label} runtime feature-superset Clippy must include ${requiredArgument}`);
    }
  }
  const normalizedCargoRuns = normalizeWorkflowCommand(cargoRuns);
  for (const obsoleteCommand of [
    "cargo clippy --locked --offline -p runtime --features cuckoo-oram --bin unified_server",
    "cargo clippy --locked --offline -p runtime --features standard-cashu-process-e2e --bin unified_server",
    "cargo clippy --locked --offline -p runtime --features cuckoo-oram,standard-cashu-process-e2e --bin unified_server",
    "cargo clippy --locked --offline -p runtime --features shared-issuer-process-e2e --bin unified_server",
  ]) {
    if (normalizedCargoRuns.includes(obsoleteCommand)) {
      fail(`${label} must not retain obsolete feature-specific runtime Clippy commands`);
    }
  }
}

export function validateWorkflowDirectory(directoryInput) {
  const directory = requireCanonicalDirectory(directoryInput, "workflow directory");
  const entries = readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  if (entries.length < 1) fail("workflow directory is empty");
  let actionUses = 0;
  let checkouts = 0;
  for (const entry of entries) {
    if (entry.isSymbolicLink() || !entry.isFile() || !/\.ya?ml$/u.test(entry.name)) {
      fail(`workflow directory contains an unreviewed entry: ${entry.name}`);
    }
    const path = resolve(directory, entry.name);
    const stat = lstatSync(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      stat.size < 1 ||
      stat.size > 2 * 1024 * 1024 ||
      realpathSync(path) !== path
    ) {
      fail(`workflow path is not one bounded canonical one-link file: ${entry.name}`);
    }
    let source;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
    } catch {
      fail(`workflow is not canonical UTF-8: ${entry.name}`);
    }
    const result = validateWorkflowSource(source, `workflow ${entry.name}`);
    if (entry.name === "workflow-supply-chain.yml") {
      validateSupplyChainGateTriggers(source, `workflow ${entry.name}`);
    }
    if (entry.name === "payment-platform.yml") {
      validatePaymentPlatformCompileAcceleration(source, `workflow ${entry.name}`);
    }
    actionUses += result.actionUses;
    checkouts += result.checkouts;
  }
  return { actionUses, checkouts, workflows: entries.length };
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  try {
    if (process.argv.length > 3) fail("usage: github-workflow-supply-chain-gate.mjs [WORKFLOW_DIRECTORY]");
    const directory = process.argv[2] ?? resolve(REPOSITORY_ROOT, ".github/workflows");
    const result = validateWorkflowDirectory(directory);
    process.stdout.write(
      `github-workflow-supply-chain-gate=PASS workflows=${result.workflows} actions=${result.actionUses} checkouts=${result.checkouts}\n`,
    );
  } catch (error) {
    process.stderr.write(`github-workflow-supply-chain-gate=FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
