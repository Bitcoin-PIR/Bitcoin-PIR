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
  EASYCRYPT_PUBLISH_PATHS,
  EASYCRYPT_VERIFIER_IMAGE,
  SUPPLY_CHAIN_GATE_PUSH_PATHS,
  validateEasyCryptVerifierPolicy,
  validateNpmParserLockBoundary,
  validatePaymentPlatformCompileAcceleration,
  validatePaymentV1CiLaneInventory,
  validateSupplyChainGateValidatorCoverage,
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
const paymentLaneScript = readFileSync(
  new URL("./payment-v1-ci-lane.sh", import.meta.url),
  "utf8",
);
const formalProofWorkflow = readFileSync(
  new URL("../.github/workflows/formal-proof.yml", import.meta.url),
  "utf8",
);
const easyCryptPublisherWorkflow = readFileSync(
  new URL("../.github/workflows/publish-easycrypt-verifier.yml", import.meta.url),
  "utf8",
);
const formalProofLock = readFileSync(
  new URL("../verification/locks/formal-proofs.json", import.meta.url),
  "utf8",
);

function mutateFormalProofLock(mutate) {
  const lock = JSON.parse(formalProofLock);
  mutate(lock);
  return `${JSON.stringify(lock, null, 2)}\n`;
}

function bootstrapFormalProofLock() {
  return mutateFormalProofLock((lock) => {
    lock.trustedVerifier.distribution = { mode: "bootstrap", image: null, provenance: null };
  });
}

test("accepts the reviewed payment-platform compile acceleration boundary", () => {
  assert.doesNotThrow(() => validatePaymentPlatformCompileAcceleration(paymentPlatformWorkflow));
});

test("accepts the reviewed payment CI lane inventory", () => {
  assert.doesNotThrow(() => validatePaymentV1CiLaneInventory(paymentLaneScript));
});

test("accepts the reviewed Phase B pinned EasyCrypt verifier", () => {
  assert.deepEqual(
    validateEasyCryptVerifierPolicy(formalProofWorkflow, easyCryptPublisherWorkflow, formalProofLock),
    {
      mode: "pinned",
      image: "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:bc174b56c1e59cfa3e8e0385fcf2dbc3332a1e433d99a59992562e56284b2d48",
    },
  );
});

test("accepts explicit Phase A bootstrap rollback without an OCI reference", () => {
  assert.deepEqual(
    validateEasyCryptVerifierPolicy(formalProofWorkflow, easyCryptPublisherWorkflow, bootstrapFormalProofLock()),
    { mode: "bootstrap", image: null },
  );
});

for (const [label, formal, publisher, lock, pattern] of [
  [
    "unconditional cold build",
    formalProofWorkflow.replace(
      "if: steps.lock.outputs.verifier_mode == 'bootstrap'\n        run: |\n          docker build",
      "run: |\n          docker build",
    ),
    easyCryptPublisherWorkflow,
    formalProofLock,
    /Phase A build/u,
  ],
  [
    "missing real proof compile",
    formalProofWorkflow.replace("easycrypt compile -I . Theorem.ec", "easycrypt --version"),
    easyCryptPublisherWorkflow,
    formalProofLock,
    /real proof/u,
  ],
  [
    "mutable Phase B pull",
    formalProofWorkflow.replace("${{ steps.lock.outputs.verifier_image }}", "ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier:latest"),
    easyCryptPublisherWorkflow,
    formalProofLock,
    /Phase B must pull/u,
  ],
  [
    "Phase B pull lacks GHCR login",
    formalProofWorkflow.replace(
      "Log in to GitHub Container Registry (Phase B)",
      "Removed GHCR login",
    ),
    easyCryptPublisherWorkflow,
    formalProofLock,
    /log in before pulling/u,
  ],
  [
    "Phase B login drops the ephemeral token",
    formalProofWorkflow.replace(
      "password: ${{ github.token }}",
      "password: ${{ secrets.UNRELATED_TOKEN }}",
    ),
    easyCryptPublisherWorkflow,
    formalProofLock,
    /GHCR login/u,
  ],
  [
    "Phase B provenance check lacks authenticated gh CLI",
    formalProofWorkflow.replace(
      "GH_TOKEN: ${{ github.token }}",
      "GH_TOKEN: missing",
    ),
    easyCryptPublisherWorkflow,
    formalProofLock,
    /Phase B verifier check/u,
  ],
  [
    "publisher provenance self-check lacks authenticated gh CLI",
    formalProofWorkflow,
    easyCryptPublisherWorkflow.replace(
      "GH_TOKEN: ${{ github.token }}",
      "GH_TOKEN: missing",
    ),
    formalProofLock,
    /publisher verification/u,
  ],
  [
    "publisher accepts pull requests",
    formalProofWorkflow,
    easyCryptPublisherWorkflow.replace("on:\n  push:", "on:\n  pull_request:\n  push:"),
    formalProofLock,
    /publisher\.on must contain exactly/u,
  ],
  [
    "publisher uses mutable latest tag",
    formalProofWorkflow,
    easyCryptPublisherWorkflow.replace(
      "bootstrap-${{ github.run_id }}-${{ github.run_attempt }}",
      "latest",
    ),
    formalProofLock,
    /unique bootstrap discovery tag/u,
  ],
  [
    "publisher can publish from a non-main ref",
    formalProofWorkflow,
    easyCryptPublisherWorkflow.replace("github.ref == 'refs/heads/main'", "always()"),
    formalProofLock,
    /fail closed outside main/u,
  ],
  [
    "publisher drops attestation",
    formalProofWorkflow,
    easyCryptPublisherWorkflow.replace("uses: actions/attest@", "uses: actions/upload-artifact@"),
    formalProofLock,
    /attest its exact pushed digest/u,
  ],
  [
    "bootstrap fabricates an image digest",
    formalProofWorkflow,
    easyCryptPublisherWorkflow,
    mutateFormalProofLock((lock) => {
      lock.trustedVerifier.distribution = {
        mode: "bootstrap",
        image: `${EASYCRYPT_VERIFIER_IMAGE}@sha256:${"a".repeat(64)}`,
        provenance: null,
      };
    }),
    /must not trust an unpublished image/u,
  ],
  [
    "pinned phase uses a mutable image reference",
    formalProofWorkflow,
    easyCryptPublisherWorkflow,
    mutateFormalProofLock((lock) => {
      lock.trustedVerifier.distribution.image = `${EASYCRYPT_VERIFIER_IMAGE}:latest`;
    }),
    /immutable reviewed GHCR digest/u,
  ],
  [
    "pinned phase uses provenance from an unprotected publisher",
    formalProofWorkflow,
    easyCryptPublisherWorkflow,
    mutateFormalProofLock((lock) => {
      lock.trustedVerifier.distribution.provenance.ref = "refs/pull/1/merge";
    }),
    /reviewed main publisher/u,
  ],
  [
    "publisher path scope expands beyond the reviewed toolchain inputs",
    formalProofWorkflow,
    easyCryptPublisherWorkflow.replace(
      "verification/toolchains/easycrypt.Dockerfile",
      "verification/**",
    ),
    formalProofLock,
    /publisher\.on\.push\.paths/u,
  ],
]) {
  test(`rejects EasyCrypt verifier regression: ${label}`, () => {
    assert.throws(() => validateEasyCryptVerifierPolicy(formal, publisher, lock), pattern);
  });
}

test("keeps the exact reviewed EasyCrypt publisher path inventory", () => {
  assert.deepEqual(EASYCRYPT_PUBLISH_PATHS, [
    ".github/workflows/publish-easycrypt-verifier.yml",
    "verification/toolchains/easycrypt.Dockerfile",
  ]);
});

for (const [label, source, pattern] of [
  ["missing core lane", paymentLaneScript.replace("  core)", "  removed)"), /core lane/u],
  ["missing root UID boundary", paymentLaneScript.replace("BPIR_REQUIRE_ROOT_CREDENTIAL_TEST=1", "BPIR_REMOVED=1"), /BPIR_REQUIRE_ROOT_CREDENTIAL_TEST/u],
  ["missing feature superset", paymentLaneScript.replace("cuckoo-oram,shared-issuer-process-e2e", "cuckoo-oram"), /cuckoo-oram,shared-issuer-process-e2e/u],
  ["missing shared issuer target", paymentLaneScript.replaceAll("payment_v1_shared_issuer_process_e2e", "payment_v1_removed_process_e2e"), /payment_v1_shared_issuer_process_e2e/u],
  ["Phase 2 feature superset regression", paymentLaneScript.replace("cuckoo-oram,shared-issuer-process-e2e", "cuckoo-oram,standard-cashu-process-e2e"), /cuckoo-oram,shared-issuer-process-e2e/u],
  ["Phase 2 obsolete Clippy returns", paymentLaneScript.replace("  runtime-features)", "  runtime-features)\n    cargo clippy --locked --offline -p runtime --features cuckoo-oram --bin unified_server --no-deps -- -D warnings"), /must not retain obsolete feature-specific runtime Clippy commands/u],
]) {
  test(`rejects lane inventory ${label}`, () => {
    assert.throws(() => validatePaymentV1CiLaneInventory(source), pattern);
  });
}

for (const [label, source, pattern] of [
  [
    "payment platform test LTO regression",
    paymentPlatformWorkflow.replaceAll('CARGO_PROFILE_TEST_LTO: "off"', 'CARGO_PROFILE_TEST_LTO: "thin"'),
    /CARGO_PROFILE_TEST_LTO=off/u,
  ],
  [
    "payment platform incremental regression",
    paymentPlatformWorkflow.replaceAll('CARGO_INCREMENTAL: "0"', 'CARGO_INCREMENTAL: "1"'),
    /CARGO_INCREMENTAL=0/u,
  ],
  [
    "payment platform sccache env regression",
    paymentPlatformWorkflow.replaceAll('SCCACHE_GHA_ENABLED: "true"', 'SCCACHE_GHA_ENABLED: "false"'),
    /SCCACHE_GHA_ENABLED=true/u,
  ],
  [
    "payment platform sccache PR write regression",
    paymentPlatformWorkflow.replace(
      "SCCACHE_GHA_RW_MODE: ${{ github.event_name == 'push' && 'READ_WRITE' || 'READ_ONLY' }}",
      'SCCACHE_GHA_RW_MODE: READ_WRITE',
    ),
    /SCCACHE_GHA_RW_MODE=/u,
  ],
  [
    "payment platform sccache PR cache mode missing",
    paymentPlatformWorkflow.replace(
      "      SCCACHE_GHA_RW_MODE: ${{ github.event_name == 'push' && 'READ_WRITE' || 'READ_ONLY' }}\n",
      "",
    ),
    /SCCACHE_GHA_RW_MODE=/u,
  ],
  [
    "payment platform sccache wrong write event",
    paymentPlatformWorkflow.replace(
      "SCCACHE_GHA_RW_MODE: ${{ github.event_name == 'push' && 'READ_WRITE' || 'READ_ONLY' }}",
      "SCCACHE_GHA_RW_MODE: ${{ github.event_name == 'workflow_dispatch' && 'READ_WRITE' || 'READ_ONLY' }}",
    ),
    /SCCACHE_GHA_RW_MODE=/u,
  ],
  [
    "payment platform mutable sccache action",
    paymentPlatformWorkflow.replaceAll(
      `mozilla-actions/sccache-action@${sccacheAction}`,
      "mozilla-actions/sccache-action@v0.0.11",
    ),
    /reviewed sccache action/u,
  ],
  [
    "payment platform target cache regression",
    paymentPlatformWorkflow.replace(
      '- name: Run protocol lane',
      `- name: Forbidden target cache\n        uses: actions/cache@${APPROVED_ACTION_COMMITS["actions/cache"]}\n      - name: Run protocol lane`,
    ),
    /must not cache the workspace target directory/u,
  ],
  [
    "payment platform timings artifact retention regression",
    paymentPlatformWorkflow.replaceAll("retention-days: 7", "retention-days: 14"),
    /seven-day retention/u,
  ],
  [
    "payment platform custom timing path missing",
    paymentPlatformWorkflow.replaceAll("target/payment-issuer-shared-e2e/cargo-timings", "target/payment-issuer-shared-e2e/missing"),
    /timing paths/u,
  ],
  [
    "payment platform broad timing path",
    paymentPlatformWorkflow.replaceAll(
      "target/payment-issuer-shared-e2e/cargo-timings",
      "target/**/cargo-timings",
    ),
    /timing paths/u,
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

const supplyChainGateWorkflow = readFileSync(
  new URL("../.github/workflows/workflow-supply-chain.yml", import.meta.url),
  "utf8",
);

test("requires the formal verifier validator mutation suite in the supply-chain gate", () => {
  assert.doesNotThrow(() => validateSupplyChainGateValidatorCoverage(supplyChainGateWorkflow));
  assert.throws(
    () => validateSupplyChainGateValidatorCoverage(
      supplyChainGateWorkflow.replace(
        "python3 -m unittest verification/scripts/test_verify_formal_lock.py",
        "true",
      ),
    ),
    /test_verify_formal_lock/u,
  );
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
