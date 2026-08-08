import assert from "node:assert/strict";
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  APPROVED_ACTION_COMMITS,
  SUPPLY_CHAIN_GATE_PUSH_PATHS,
  validateNpmParserLockBoundary,
  validatePaymentPlatformCompileAcceleration,
  validateSupplyChainGateTriggers,
  validateWorkflowDirectory,
  validateWorkflowSource,
} from "./github-workflow-supply-chain-gate.mjs";

const checkout = APPROVED_ACTION_COMMITS["actions/checkout"];
const setupNode = APPROVED_ACTION_COMMITS["actions/setup-node"];
const sccacheAction = APPROVED_ACTION_COMMITS["mozilla-actions/sccache-action"];

function workflow(stepSource = `
      - name: Checkout
        uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
`) {
  return `
name: Fixture
on:
  pull_request:
permissions:
  contents: read
jobs:
  fixture:
    runs-on: ubuntu-24.04
    steps:
${stepSource}`;
}

test("accepts exact allowlisted commits and non-persisting checkout credentials", () => {
  const result = validateWorkflowSource(workflow(`
      - name: Checkout
        uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
      - name: Setup Node
        uses: actions/setup-node@${setupNode}
`));
  assert.deepEqual(result, { actionUses: 2, checkouts: 1 });
});

test("accepts the reviewed exact sccache action pin", () => {
  const result = validateWorkflowSource(workflow(`
      - uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
      - uses: mozilla-actions/sccache-action@${sccacheAction}
`));
  assert.deepEqual(result, { actionUses: 2, checkouts: 1 });
});

const paymentPlatformWorkflow = readFileSync(
  new URL("../.github/workflows/payment-platform.yml", import.meta.url),
  "utf8",
);

test("accepts the reviewed payment-platform compile acceleration boundary", () => {
  assert.doesNotThrow(() => validatePaymentPlatformCompileAcceleration(paymentPlatformWorkflow));
});

for (const [label, source, pattern] of [
  [
    "payment platform test LTO regression",
    paymentPlatformWorkflow.replace('CARGO_PROFILE_TEST_LTO: "off"', 'CARGO_PROFILE_TEST_LTO: "thin"'),
    /CARGO_PROFILE_TEST_LTO=off/u,
  ],
  [
    "payment platform incremental regression",
    paymentPlatformWorkflow.replace('CARGO_INCREMENTAL: "0"', 'CARGO_INCREMENTAL: "1"'),
    /CARGO_INCREMENTAL=0/u,
  ],
  [
    "payment platform sccache env regression",
    paymentPlatformWorkflow.replace('SCCACHE_GHA_ENABLED: "true"', 'SCCACHE_GHA_ENABLED: "false"'),
    /SCCACHE_GHA_ENABLED=true/u,
  ],
  [
    "payment platform mutable sccache action",
    paymentPlatformWorkflow.replace(
      `mozilla-actions/sccache-action@${sccacheAction}`,
      "mozilla-actions/sccache-action@v0.0.11",
    ),
    /reviewed sccache action/u,
  ],
  [
    "payment platform target cache regression",
    paymentPlatformWorkflow.replace(
      "- name: Test payment platform offline",
      `- name: Forbidden target cache\n        uses: actions/cache@${APPROVED_ACTION_COMMITS["actions/cache"]}\n      - name: Test payment platform offline`,
    ),
    /must not cache the workspace target directory/u,
  ],
  [
    "payment platform timings artifact retention regression",
    paymentPlatformWorkflow.replace("retention-days: 7", "retention-days: 14"),
    /seven-day retention/u,
  ],
  [
    "payment platform custom timing path missing",
    paymentPlatformWorkflow.replace("\n            target/payment-issuer-shared-e2e/cargo-timings", ""),
    /Cargo timing artifact paths/u,
  ],
  [
    "payment platform broad timing path",
    paymentPlatformWorkflow.replace(
      "target/payment-issuer-shared-e2e/cargo-timings",
      "target/**/cargo-timings",
    ),
    /Cargo timing artifact paths/u,
  ],
]) {
  test(`rejects ${label}`, () => {
    assert.throws(() => validatePaymentPlatformCompileAcceleration(source), pattern);
  });
}

for (const [label, source, pattern] of [
  ["mutable tag", workflow(`
      - uses: actions/checkout@v7.0.1
        with:
          persist-credentials: false
`), /lowercase 40-hex/u],
  ["mutable sccache tag", workflow(`
      - uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
      - uses: mozilla-actions/sccache-action@v0.0.11
`), /lowercase 40-hex/u],
  ["wrong sccache commit", workflow(`
      - uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
      - uses: mozilla-actions/sccache-action@${"1".repeat(40)}
`), /allowlist/u],
  ["unknown exact action", workflow(`
      - uses: example/unknown@${"1".repeat(40)}
`), /allowlist/u],
  ["wrong checkout commit", workflow(`
      - uses: actions/checkout@${"1".repeat(40)}
        with:
          persist-credentials: false
`), /allowlist/u],
  ["missing checkout with", workflow(`
      - uses: actions/checkout@${checkout}
`), /persist-credentials/u],
  ["persisted checkout", workflow(`
      - uses: actions/checkout@${checkout}
        with:
          persist-credentials: true
`), /persist-credentials/u],
  ["string false checkout", workflow(`
      - uses: actions/checkout@${checkout}
        with:
          persist-credentials: "false"
`), /YAML boolean/u],
  ["expression action", workflow(`
      - uses: \${{ matrix.action }}
`), /lowercase 40-hex/u],
  ["local action bypass", workflow(`
      - uses: ./unreviewed-action
`), /lowercase 40-hex/u],
  ["reusable mutable workflow", workflow(`
      - uses: owner/repository/.github/workflows/reuse.yml@main
`), /lowercase 40-hex/u],
  ["reusable exact workflow", workflow(`
      - uses: owner/repository/.github/workflows/reuse.yml@${"1".repeat(40)}
`), /allowlist/u],
  ["Docker action", workflow(`
      - uses: docker://alpine:3.22
`), /lowercase 40-hex/u],
  ["bare YAML anchor", workflow(`
      - &checkout
        uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
`), /anchors/u],
  ["YAML alias", workflow(`
      - &checkout
        uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
      - *checkout
`), /aliases|anchors/u],
  ["YAML merge key", workflow(`
      - <<:
          uses: actions/checkout@${checkout}
          with:
            persist-credentials: false
`), /merge keys/u],
  ["duplicate YAML key", workflow(`
      - uses: actions/checkout@${checkout}
        uses: actions/checkout@${checkout}
        with:
          persist-credentials: false
`), /strict warning-free YAML/u],
]) {
  test(`rejects ${label}`, () => {
    assert.throws(() => validateWorkflowSource(source, label), pattern);
  });
}

test("rejects workflows without an approved checkout", () => {
  assert.throws(
    () => validateWorkflowSource(workflow(`
      - uses: actions/setup-node@${setupNode}
`)),
    /checkout/u,
  );
});

test("accepts the parser lock boundary without npm-shrinkwrap.json", (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-parser-lock-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, "web"), { mode: 0o700 });
  writeFileSync(join(root, "web", "package-lock.json"), "{}\n", { mode: 0o600 });
  assert.doesNotThrow(() => validateNpmParserLockBoundary(root));
});

test("rejects higher-priority npm-shrinkwrap.json parser lock", (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-parser-lock-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, "web"), { mode: 0o700 });
  writeFileSync(join(root, "web", "package-lock.json"), "{}\n", { mode: 0o600 });
  writeFileSync(join(root, "web", "npm-shrinkwrap.json"), "{}\n", { mode: 0o600 });
  assert.throws(
    () => validateNpmParserLockBoundary(root),
    /forbidden because npm gives it precedence/u,
  );
});

test("rejects a dangling npm-shrinkwrap.json symlink", (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-parser-lock-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, "web"), { mode: 0o700 });
  symlinkSync("missing-lock", join(root, "web", "npm-shrinkwrap.json"));
  assert.throws(
    () => validateNpmParserLockBoundary(root),
    /forbidden because npm gives it precedence/u,
  );
});

function supplyChainGateTriggerFixture({ mergeGroup = true, pullRequestPaths = false } = {}) {
  const pushPaths = SUPPLY_CHAIN_GATE_PUSH_PATHS
    .map((path) => `      - '${path}'`)
    .join("\n");
  const pullRequestPathFilter = pullRequestPaths
    ? "    paths: ['.github/workflows/**']\n"
    : "";
  const mergeGroupTrigger = mergeGroup
    ? "  merge_group:\n    types: [checks_requested]\n"
    : "";
  return `
name: GitHub workflow supply-chain gate
on:
  push:
    branches: [main]
    paths:
${pushPaths}
  pull_request:
    branches: [main]
${pullRequestPathFilter}${mergeGroupTrigger}  workflow_dispatch:
`;
}

test("accepts always-reporting PR and merge-queue gate triggers", () => {
  assert.deepEqual(validateSupplyChainGateTriggers(supplyChainGateTriggerFixture()), {
    events: 4,
    pushPaths: SUPPLY_CHAIN_GATE_PUSH_PATHS.length,
  });
});

test("rejects a PR path filter that can strand a required check", () => {
  assert.throws(
    () => validateSupplyChainGateTriggers(
      supplyChainGateTriggerFixture({ pullRequestPaths: true }),
    ),
    /on\.pull_request must contain exactly/u,
  );
});

test("rejects a gate without merge-group coverage", () => {
  assert.throws(
    () => validateSupplyChainGateTriggers(supplyChainGateTriggerFixture({ mergeGroup: false })),
    /on must contain exactly/u,
  );
});

function workflowDirectory(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bitcoinpir-workflow-gate-")));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const directory = join(root, "workflows");
  mkdirSync(directory, { mode: 0o700 });
  writeFileSync(join(directory, "fixture.yml"), workflow(), { mode: 0o600 });
  return directory;
}

test("accepts a canonical directory of one-link workflow files", (t) => {
  assert.deepEqual(validateWorkflowDirectory(workflowDirectory(t)), {
    actionUses: 1,
    checkouts: 1,
    workflows: 1,
  });
});

test("rejects an extra non-workflow directory entry", (t) => {
  const directory = workflowDirectory(t);
  writeFileSync(join(directory, "README"), "unreviewed\n");
  assert.throws(() => validateWorkflowDirectory(directory), /unreviewed entry/u);
});

test("rejects a symlinked workflow", (t) => {
  const directory = workflowDirectory(t);
  symlinkSync(join(directory, "fixture.yml"), join(directory, "linked.yml"));
  assert.throws(() => validateWorkflowDirectory(directory), /unreviewed entry/u);
});

test("rejects hardlinked workflows", (t) => {
  const directory = workflowDirectory(t);
  linkSync(join(directory, "fixture.yml"), join(directory, "linked.yml"));
  assert.throws(() => validateWorkflowDirectory(directory), /one-link/u);
});

test("rejects non-UTF-8 workflow bytes", (t) => {
  const directory = workflowDirectory(t);
  writeFileSync(join(directory, "fixture.yml"), Buffer.from([0xff, 0xfe, 0xfd]));
  assert.throws(() => validateWorkflowDirectory(directory), /canonical UTF-8/u);
});
