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
  "actions/attest": "1e69f48acb82d1966a394da916b4c1698aa569d6",
  "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
  "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "actions/upload-pages-artifact": "fc324d3547104276b827a68afc52ff2a11cc49c9",
  "mozilla-actions/sccache-action": "fc920bf0ec8de6ee65d409111f7ec508035751ba",
  "docker/build-push-action": "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
  "docker/login-action": "dbcb813823bdd20940b903addbd779551569679f",
  "docker/setup-buildx-action": "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
});

export const EASYCRYPT_VERIFIER_IMAGE = "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier";
export const EASYCRYPT_PUBLISH_WORKFLOW = ".github/workflows/publish-easycrypt-verifier.yml";
export const EASYCRYPT_PUBLISH_PATHS = Object.freeze([
  ".github/workflows/publish-easycrypt-verifier.yml",
  "verification/toolchains/easycrypt.Dockerfile",
]);

export const SUPPLY_CHAIN_GATE_PUSH_PATHS = Object.freeze([
  ".github/workflows/**",
  "scripts/github-workflow-supply-chain-gate.mjs",
  "scripts/github-workflow-supply-chain-gate.test.mjs",
  "web/package.json",
  "web/package-lock.json",
  "web/npm-shrinkwrap.json",
  "verification/locks/formal-proofs.json",
  "verification/scripts/verify_formal_lock.py",
  "verification/scripts/test_verify_formal_lock.py",
  "verification/toolchains/easycrypt.Dockerfile",
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

export function validateSupplyChainGateValidatorCoverage(
  source,
  label = "workflow supply-chain gate",
) {
  const workflow = parseWorkflowSource(source, label);
  const steps = workflow.jobs?.["workflow-supply-chain"]?.steps;
  if (!Array.isArray(steps)) fail(`${label} must retain its validation steps`);
  const policyStep = requireWorkflowStep(
    steps,
    (step) => step.name === "Validate workflow supply-chain policy" && typeof step.run === "string",
    `${label} must retain workflow policy validation`,
  );
  for (const command of [
    "node --test scripts/github-workflow-supply-chain-gate.test.mjs",
    "node scripts/github-workflow-supply-chain-gate.mjs",
    "python3 -m py_compile verification/scripts/verify_formal_lock.py verification/scripts/test_verify_formal_lock.py",
    "python3 -m unittest verification/scripts/test_verify_formal_lock.py",
  ]) {
    if (!policyStep.run.includes(command)) {
      fail(`${label} must execute ${command}`);
    }
  }
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

function requireExactPermissionMapping(value, expected, label) {
  requireExactMappingKeys(value, Object.keys(expected), label);
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value[key] !== expectedValue) fail(`${label}.${key} must equal ${expectedValue}`);
  }
}

function requireRunStep(steps, name, label) {
  return requireWorkflowStep(
    steps,
    (step) => step.name === name && typeof step.run === "string",
    label,
  );
}

function parseFormalVerifierLock(lockSource, label) {
  let lock;
  try {
    lock = JSON.parse(lockSource);
  } catch {
    fail(`${label} must be strict JSON`);
  }
  if (!isRecord(lock) || !isRecord(lock.trustedVerifier)) {
    fail(`${label} must contain trustedVerifier`);
  }
  const verifier = lock.trustedVerifier;
  requireExactMappingKeys(
    verifier,
    [
      "altErgoVersion",
      "baseImage",
      "command",
      "distribution",
      "dockerfilePath",
      "dockerfileSha256",
      "easycryptCommit",
      "easycryptRepository",
      "ocamlVersion",
      "platform",
      "schema",
      "why3Version",
    ],
    `${label}.trustedVerifier`,
  );
  if (verifier.schema !== "BitcoinPIR/product-owned-easycrypt-verifier/v2") {
    fail(`${label}.trustedVerifier must use the reviewed v2 schema`);
  }
  if (!isRecord(verifier.distribution)) fail(`${label}.trustedVerifier.distribution must be a mapping`);
  requireExactMappingKeys(
    verifier.distribution,
    ["image", "mode", "provenance"],
    `${label}.trustedVerifier.distribution`,
  );
  const distribution = verifier.distribution;
  if (distribution.mode === "bootstrap") {
    if (distribution.image !== null || distribution.provenance !== null) {
      fail(`${label} bootstrap distribution must not trust an unpublished image`);
    }
    return { mode: "bootstrap", image: null };
  }
  if (distribution.mode !== "pinned") fail(`${label} verifier distribution mode is unsupported`);
  if (
    typeof distribution.image !== "string" ||
    !new RegExp(`^${EASYCRYPT_VERIFIER_IMAGE.replaceAll("/", "\\/")}@sha256:[0-9a-f]{64}$`, "u").test(distribution.image)
  ) {
    fail(`${label} pinned verifier image must be the immutable reviewed GHCR digest`);
  }
  if (!isRecord(distribution.provenance)) fail(`${label} pinned verifier provenance must be a mapping`);
  requireExactMappingKeys(
    distribution.provenance,
    ["commit", "dockerfileSha256", "ref", "repository", "workflow"],
    `${label}.trustedVerifier.distribution.provenance`,
  );
  if (
    distribution.provenance.repository !== "Bitcoin-PIR/Bitcoin-PIR" ||
    distribution.provenance.workflow !== EASYCRYPT_PUBLISH_WORKFLOW ||
    distribution.provenance.ref !== "refs/heads/main" ||
    !/^[0-9a-f]{40}$/u.test(distribution.provenance.commit) ||
    distribution.provenance.dockerfileSha256 !== verifier.dockerfileSha256
  ) {
    fail(`${label} pinned verifier provenance must bind the reviewed main publisher and Dockerfile`);
  }
  return { mode: "pinned", image: distribution.image };
}

export function validateEasyCryptVerifierPolicy(
  formalSource,
  publishSource,
  lockSource,
  label = "EasyCrypt verifier policy",
) {
  const distribution = parseFormalVerifierLock(lockSource, `${label} lock`);
  const formal = parseWorkflowSource(formalSource, `${label} formal workflow`);
  requireExactPermissionMapping(
    formal.permissions,
    { attestations: "read", contents: "read", packages: "read" },
    `${label} formal workflow.permissions`,
  );
  const formalSteps = formal.jobs?.verify?.steps;
  if (!Array.isArray(formalSteps)) fail(`${label} formal workflow must retain verify steps`);
  const bootstrap = requireRunStep(
    formalSteps,
    "Build product-owned trusted EasyCrypt verifier (Phase A bootstrap)",
    `${label} must retain an explicit Phase A build`,
  );
  if (
    bootstrap.if !== "steps.lock.outputs.verifier_mode == 'bootstrap'" ||
    !bootstrap.run.includes("docker build") ||
    !bootstrap.run.includes("verification/toolchains/easycrypt.Dockerfile")
  ) {
    fail(`${label} Phase A build must be only validator-selected bootstrap`);
  }
  const consumerLogin = requireWorkflowStep(
    formalSteps,
    (step) => step.name === "Log in to GitHub Container Registry (Phase B)" && typeof step.uses === "string",
    `${label} must log in before pulling a Phase B package`,
  );
  if (
    consumerLogin.if !== "steps.lock.outputs.verifier_mode == 'pinned'" ||
    consumerLogin.uses !== `docker/login-action@${APPROVED_ACTION_COMMITS["docker/login-action"]}` ||
    consumerLogin.with?.registry !== "ghcr.io" ||
    consumerLogin.with?.username !== "${{ github.actor }}" ||
    consumerLogin.with?.password !== "${{ github.token }}"
  ) {
    fail(`${label} Phase B GHCR login must use the reviewed action and ephemeral GitHub token`);
  }
  const pull = requireRunStep(
    formalSteps,
    "Pull product-owned trusted EasyCrypt verifier (Phase B)",
    `${label} must retain Phase B immutable pull`,
  );
  if (
    pull.if !== "steps.lock.outputs.verifier_mode == 'pinned'" ||
    !pull.run.includes('docker pull "${{ steps.lock.outputs.verifier_image }}"')
  ) {
    fail(`${label} Phase B must pull only the lock-selected digest`);
  }
  const verify = requireRunStep(
    formalSteps,
    "Verify prebuilt verifier identity and provenance (Phase B)",
    `${label} must verify the Phase B image`,
  );
  for (const required of [
    "docker image inspect",
    "RepoDigests",
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "gh attestation verify",
    "--signer-workflow",
    "--source-ref refs/heads/main",
    "--source-digest",
  ]) {
    if (
      verify.if !== "steps.lock.outputs.verifier_mode == 'pinned'" ||
      verify.env?.GH_TOKEN !== "${{ github.token }}" ||
      !verify.run.includes(required)
    ) {
      fail(`${label} Phase B verifier check must retain ${required}`);
    }
  }
  const compile = requireRunStep(
    formalSteps,
    "Re-run locked proof with trusted command",
    `${label} must retain real EasyCrypt compile`,
  );
  if (!compile.run.includes("easycrypt compile -I . Theorem.ec") || !compile.run.includes("${{ steps.verifier.outputs.image }}")) {
    fail(`${label} must re-run the real proof through the selected verifier image`);
  }

  const publish = parseWorkflowSource(publishSource, `${label} publisher workflow`);
  requireExactMappingKeys(publish.on, ["push", "schedule", "workflow_dispatch"], `${label} publisher.on`);
  requireExactMappingKeys(publish.on.push, ["branches", "paths"], `${label} publisher.on.push`);
  requireExactStringList(publish.on.push.branches, ["main"], `${label} publisher.on.push.branches`);
  requireExactStringList(publish.on.push.paths, EASYCRYPT_PUBLISH_PATHS, `${label} publisher.on.push.paths`);
  if (!Array.isArray(publish.on.schedule) || publish.on.schedule.length !== 1 || publish.on.schedule[0]?.cron !== "17 4 * * 1") {
    fail(`${label} publisher must retain its weekly clean rebuild`);
  }
  if (publish.on.workflow_dispatch !== null) fail(`${label} publisher dispatch must remain input-free`);
  requireExactPermissionMapping(publish.permissions, { contents: "read" }, `${label} publisher.permissions`);
  const publishJob = publish.jobs?.publish;
  if (!isRecord(publishJob) || publishJob.if !== "github.ref == 'refs/heads/main'") {
    fail(`${label} publisher must fail closed outside main`);
  }
  requireExactPermissionMapping(
    publishJob.permissions,
    { attestations: "write", contents: "read", "id-token": "write", packages: "write" },
    `${label} publisher job.permissions`,
  );
  const publishSteps = publishJob.steps;
  if (!Array.isArray(publishSteps)) fail(`${label} publisher must contain steps`);
  const build = requireWorkflowStep(
    publishSteps,
    (step) => step.id === "build" && typeof step.uses === "string",
    `${label} publisher must build the image`,
  );
  if (
    build.uses !== `docker/build-push-action@${APPROVED_ACTION_COMMITS["docker/build-push-action"]}` ||
    build.with?.platforms !== "linux/amd64" ||
    build.with?.push !== true ||
    build.with?.provenance !== false ||
    build.with?.tags !== "${{ env.IMAGE }}:bootstrap-${{ github.run_id }}-${{ github.run_attempt }}" ||
    typeof build.with?.tags !== "string" || build.with.tags.includes("latest")
  ) {
    fail(`${label} publisher must emit only a unique bootstrap discovery tag and immutable digest`);
  }
  const attest = requireWorkflowStep(
    publishSteps,
    (step) => step.id === "attest" && typeof step.uses === "string",
    `${label} publisher must attest the image digest`,
  );
  if (
    attest.uses !== `actions/attest@${APPROVED_ACTION_COMMITS["actions/attest"]}` ||
    attest.with?.["subject-name"] !== "${{ env.IMAGE }}" ||
    attest.with?.["subject-digest"] !== "${{ steps.build.outputs.digest }}" ||
    attest.with?.["push-to-registry"] !== true ||
    attest.with?.["create-storage-record"] !== false
  ) {
    fail(`${label} publisher must attest its exact pushed digest without extra metadata permission`);
  }
  const publishVerify = requireRunStep(
    publishSteps,
    "Verify published provenance before reporting the digest",
    `${label} publisher must verify its attestation`,
  );
  for (const required of ["gh attestation verify", "--signer-workflow", "--source-ref refs/heads/main", "--source-digest \"$GITHUB_SHA\""]) {
    if (
      publishVerify.env?.GH_TOKEN !== "${{ github.token }}" ||
      !publishVerify.run.includes(required)
    ) {
      fail(`${label} publisher verification must retain ${required}`);
    }
  }
  return { mode: distribution.mode, image: distribution.image };
}

export function validatePaymentPlatformCompileAcceleration(
  source,
  label = "payment platform workflow",
) {
  const workflow = parseWorkflowSource(source, label);
  const laneJob = workflow.jobs?.["protocol-and-persistence-lanes"];
  if (isRecord(laneJob)) {
    if (Object.hasOwn(workflow.jobs, "protocol-and-persistence-legacy")) fail(`${label} must not retain a legacy protocol job`);
    const expectedEnv = { CARGO_PROFILE_TEST_LTO: "off", CARGO_INCREMENTAL: "0", SCCACHE_GHA_ENABLED: "true", SCCACHE_GHA_RW_MODE: "${{ github.event_name == 'push' && 'READ_WRITE' || 'READ_ONLY' }}", RUSTC_WRAPPER: "sccache" };
    if (!isRecord(laneJob.env)) fail(`${label} protocol lanes must define compiler-cache env`);
    for (const [key, value] of Object.entries(expectedEnv)) if (laneJob.env[key] !== value) fail(`${label} protocol lanes must set ${key}=${value}`);
    if (!isRecord(laneJob.strategy) || !isRecord(laneJob.strategy.matrix) || laneJob.strategy["fail-fast"] !== false) fail(`${label} protocol lanes must use fail-fast=false matrix`);
    const lanes = laneJob.strategy.matrix.include;
    if (!Array.isArray(lanes) || lanes.length !== 4) fail(`${label} protocol lanes must define exactly four lanes`);
    requireExactStringList(lanes.map((entry) => entry.lane), ["core", "runtime-default-security", "runtime-features", "issuer-directory-tools"], `${label} protocol lane names`);
    const steps = laneJob.steps;
    if (!Array.isArray(steps)) fail(`${label} protocol lane steps must be a list`);
    if (steps.some((step) => typeof step.run === "string" && /\bcargo\s/u.test(step.run))) fail(`${label} protocol lanes must not retain inline Cargo commands`);
    if (steps.some((step) => typeof step.uses === "string" && step.uses.startsWith("actions/cache@"))) fail(`${label} protocol lanes must not cache the workspace target directory`);
    const timingPaths = Object.fromEntries(lanes.map((entry) => [entry.lane, entry.timing_paths]));
    if (timingPaths.core !== "target/cargo-timings" || timingPaths["runtime-default-security"] !== "target/cargo-timings" || timingPaths["issuer-directory-tools"] !== "target/cargo-timings" || timingPaths["runtime-features"] !== "target/cargo-timings\ntarget/payment-issuer-shared-e2e/cargo-timings") fail(`${label} protocol lane timing paths must be exact`);
    const sccacheAction = `mozilla-actions/sccache-action@${APPROVED_ACTION_COMMITS["mozilla-actions/sccache-action"]}`;
    requireWorkflowStep(steps, (step) => step.uses === sccacheAction, `${label} protocol lanes must install the reviewed sccache action`);
    requireWorkflowStep(steps, (step) => step.run === 'bash scripts/payment-v1-ci-lane.sh --lane "${{ matrix.lane }}"', `${label} protocol lanes must use the reviewed lane entrypoint`);
    requireWorkflowStep(steps, (step) => step.if === "always()" && typeof step.run === "string" && step.run.includes("--show-stats"), `${label} protocol lanes must report sccache stats`);
    const artifact = requireWorkflowStep(steps, (step) => step.if === "always()" && step.uses === `actions/upload-artifact@${APPROVED_ACTION_COMMITS["actions/upload-artifact"]}`, `${label} protocol lanes must upload timing reports`);
    if (artifact.with?.path !== "${{ matrix.timing_paths }}" || artifact.with?.["retention-days"] !== 7 || artifact.with?.["if-no-files-found"] !== "ignore") fail(`${label} protocol lanes must upload only seven-day retention matrix timing reports`);
    const aggregate = workflow.jobs["protocol-and-persistence"];
    if (!isRecord(aggregate) || aggregate.name !== "Protocol, stores, adapters, issuer and runtime" || aggregate.if !== "${{ always() }}" || aggregate.needs !== "protocol-and-persistence-lanes") fail(`${label} must preserve the stable protocol aggregate required check`);
    const browser = workflow.jobs["browser-storage-boundary"];
    if (!isRecord(browser) || browser.if !== "${{ github.event_name == 'workflow_dispatch' && inputs.run_browser_checks }}") fail(`${label} Chromium browser boundary must be explicit-dispatch opt-in`);
    return;
  }
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

export function validatePaymentV1CiLaneInventory(source, label = "payment CI lane script") {
  for (const lane of ["core", "runtime-default-security", "runtime-features", "issuer-directory-tools"]) {
    if (!source.includes(`  ${lane})`)) fail(`${label} must define the ${lane} lane`);
  }
  for (const requiredCommand of [
    "BPIR_REQUIRE_ROOT_CREDENTIAL_TEST=1",
    "test-only-unsafe-query-logging",
    "remote-authority-process-e2e",
    "cuckoo-oram,shared-issuer-process-e2e",
    "payment_v1_shared_issuer_process_e2e",
    "test-only-fake-lightning",
    "payment_v1_two_relay_process_e2e",
    "cdk_nut03_interop",
    "generate-payment-v1-no-funds.sh",
  ]) {
    if (!source.includes(requiredCommand)) fail(`${label} must inventory ${requiredCommand}`);
  }
  for (const obsoleteFeature of ["--features cuckoo-oram --bin unified_server", "--features standard-cashu-process-e2e --bin unified_server", "--features cuckoo-oram,standard-cashu-process-e2e --bin unified_server", "--features shared-issuer-process-e2e --bin unified_server"]) {
    if (source.includes(obsoleteFeature)) fail(`${label} must not retain obsolete feature-specific runtime Clippy commands`);
  }
}

export function validateWorkflowDirectory(directoryInput) {
  const directory = requireCanonicalDirectory(directoryInput, "workflow directory");
  const entries = readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  if (entries.length < 1) fail("workflow directory is empty");
  let actionUses = 0;
  let checkouts = 0;
  const workflowSources = new Map();
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
    workflowSources.set(entry.name, source);
    if (entry.name === "workflow-supply-chain.yml") {
      validateSupplyChainGateTriggers(source, `workflow ${entry.name}`);
      validateSupplyChainGateValidatorCoverage(source, `workflow ${entry.name}`);
    }
    if (entry.name === "payment-platform.yml") {
      validatePaymentPlatformCompileAcceleration(source, `workflow ${entry.name}`);
    }
    actionUses += result.actionUses;
    checkouts += result.checkouts;
  }
  const formalSource = workflowSources.get("formal-proof.yml");
  const publishSource = workflowSources.get("publish-easycrypt-verifier.yml");
  if (formalSource !== undefined || publishSource !== undefined) {
    if (formalSource === undefined || publishSource === undefined) {
      fail("formal proof and EasyCrypt publisher workflows must be reviewed together");
    }
    const lockPath = resolve(REPOSITORY_ROOT, "verification/locks/formal-proofs.json");
    let lockSource;
    try {
      lockSource = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(lockPath));
    } catch {
      fail("formal proof lock must be canonical UTF-8");
    }
    validateEasyCryptVerifierPolicy(formalSource, publishSource, lockSource);
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
