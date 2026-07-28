#!/usr/bin/env node

import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const EXPECTED_DEPLOY_CONDITION =
  "${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && inputs.confirm_production_deploy }}";

function fail(message) {
  throw new Error(`pages-deploy-gate: ${message}`);
}

let parseDocument;
let visit;
try {
  const requireFromWeb = createRequire(
    resolve(REPOSITORY_ROOT, 'web/package.json'),
  );
  ({ parseDocument, visit } = requireFromWeb('yaml'));
} catch {
  fail('locked YAML parser unavailable; run npm ci in web first');
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireRecord(value, label) {
  if (!isRecord(value)) {
    fail(`${label} must be a mapping`);
  }
  return value;
}

function requireExactKeys(value, expectedKeys, label) {
  const mapping = requireRecord(value, label);
  const actualKeys = Object.keys(mapping).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpected.length ||
    actualKeys.some((key, index) => key !== sortedExpected[index])
  ) {
    fail(`${label} keys must be exactly: ${sortedExpected.join(', ')}`);
  }
  return mapping;
}

function requireExactMapping(value, expected, label) {
  const expectedKeys = Object.keys(expected).sort();
  const mapping = requireExactKeys(value, expectedKeys, label);
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (!Object.is(mapping[key], expectedValue)) {
      fail(`${label} must set ${key} to ${String(expectedValue)}`);
    }
  }
  return mapping;
}

function rejectMergeKeys(value, label, seen = new Set()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) {
    return;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      rejectMergeKeys(item, label, seen);
    }
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (key === '<<') {
      fail(`${label} contains a forbidden YAML merge key`);
    }
    rejectMergeKeys(child, label, seen);
  }
}

function parseWorkflowSource(source, label) {
  const document = parseDocument(source, {
    version: '1.2',
    schema: 'core',
    strict: true,
    stringKeys: true,
    uniqueKeys: true,
    merge: false,
    logLevel: 'silent',
  });
  if (document.errors.length > 0) {
    fail(`${label} YAML parse failed: ${document.errors[0].message}`);
  }
  if (document.warnings.length > 0) {
    fail(`${label} YAML warning is forbidden: ${document.warnings[0].message}`);
  }
  visit(document, {
    Alias() {
      fail(`${label} contains a forbidden YAML alias`);
    },
    Node(_key, node) {
      if (node.anchor !== undefined) {
        fail(`${label} contains a forbidden YAML anchor`);
      }
    },
  });
  let workflow;
  try {
    workflow = document.toJS({ maxAliasCount: 0 });
  } catch (error) {
    fail(`${label} YAML conversion failed: ${String(error)}`);
  }
  requireRecord(workflow, label);
  rejectMergeKeys(workflow, label);
  return workflow;
}

function walk(value, path, visitor, seen = new Set()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) {
    return;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((child, index) => {
      visitor(index, child, [...path, index]);
      walk(child, [...path, index], visitor, seen);
    });
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    visitor(key, child, [...path, key]);
    walk(child, [...path, key], visitor, seen);
  }
}

function findPagesCapabilities(workflow) {
  const findings = [];
  walk(workflow, [], (key, value, path) => {
    if (key === 'permissions') {
      if (value === 'write-all') {
        findings.push({ kind: 'write-all', path });
      } else if (isRecord(value)) {
        if (value.pages === 'write') {
          findings.push({ kind: 'pages-write', path: [...path, 'pages'] });
        }
        if (value.actions === 'write') {
          findings.push({ kind: 'actions-write', path: [...path, 'actions'] });
        }
      }
    }
    if (
      key === 'uses' &&
      typeof value === 'string' &&
      /^actions\/(configure|deploy)-pages@/i.test(value)
    ) {
      findings.push({
        kind: /^actions\/configure-pages@/i.test(value)
          ? 'configure-pages'
          : 'deploy-pages',
        path,
      });
    }
    if (
      key === 'uses' &&
      typeof value === 'string' &&
      path.length === 3 &&
      path[0] === 'jobs'
    ) {
      findings.push({ kind: 'reusable-workflow', path });
    }
  });
  return findings;
}

function verifyReadOnlyWorkflowPermissions(workflow, label) {
  requireExactMapping(
    workflow.permissions,
    { contents: 'read' },
    `${label} permissions`,
  );
  const jobs = requireRecord(workflow.jobs, `${label} jobs`);
  for (const [jobName, jobValue] of Object.entries(jobs)) {
    const job = requireRecord(jobValue, `${label} job ${jobName}`);
    if (Object.hasOwn(job, 'permissions')) {
      requireExactMapping(
        job.permissions,
        { contents: 'read' },
        `${label} job ${jobName} permissions`,
      );
    }
  }
}

function canDeploy({ eventName, ref, confirmed, buildSucceeded }) {
  return (
    eventName === 'workflow_dispatch' &&
    ref === 'refs/heads/main' &&
    confirmed === true &&
    buildSucceeded === true
  );
}

function verifySelfTests() {
  const cases = [
    ['push main', 'push', 'refs/heads/main', true, true, false],
    ['dispatch feature', 'workflow_dispatch', 'refs/heads/feature', true, true, false],
    ['dispatch unconfirmed', 'workflow_dispatch', 'refs/heads/main', false, true, false],
    ['dispatch failed build', 'workflow_dispatch', 'refs/heads/main', true, false, false],
    ['dispatch confirmed main', 'workflow_dispatch', 'refs/heads/main', true, true, true],
  ];
  for (const [label, eventName, ref, confirmed, buildSucceeded, expected] of cases) {
    if (canDeploy({ eventName, ref, confirmed, buildSucceeded }) !== expected) {
      fail(`truth-table mismatch for ${label}`);
    }
  }

  const semanticControls = [
    String.raw`permissions: { "pa\u0067es": write }`,
    String.raw`uses: "actions/deploy\u002dpages@0123456789abcdef"`,
    'permissions: write-all',
    String.raw`permissions: { "act\u0069ons": write }`,
    'jobs: { delegated: { uses: owner/repo/.github/workflows/deploy.yml@main } }',
  ];
  for (const source of semanticControls) {
    const parsed = parseWorkflowSource(source, 'semantic positive control');
    if (findPagesCapabilities(parsed).length !== 1) {
      fail('semantic Pages detector rejected a positive control');
    }
  }
  const negative = parseWorkflowSource(
    'permissions:\n  contents: read\n',
    'semantic negative control',
  );
  if (findPagesCapabilities(negative).length !== 0) {
    fail('semantic Pages detector accepted its negative control');
  }

  const readOnlySibling = parseWorkflowSource(
    'permissions: { contents: read }\njobs: { test: { runs-on: ubuntu-latest } }\n',
    'read-only sibling control',
  );
  verifyReadOnlyWorkflowPermissions(readOnlySibling, 'read-only sibling control');
  const writableSibling = parseWorkflowSource(
    'permissions: { contents: read }\njobs: { test: { permissions: { contents: write } } }\n',
    'writable sibling control',
  );
  let writableSiblingRejected = false;
  try {
    verifyReadOnlyWorkflowPermissions(writableSibling, 'writable sibling control');
  } catch (error) {
    writableSiblingRejected = String(error).includes(
      'pages-deploy-gate: writable sibling control job test permissions',
    );
  }
  if (!writableSiblingRejected) {
    fail('sibling job-level write permission control was not rejected');
  }
}

function verifyDeployWorkflow(workflowPath) {
  const workflow = parseWorkflowSource(
    readFileSync(workflowPath, 'utf8'),
    'deployment workflow',
  );
  requireExactMapping(workflow.permissions, { contents: 'read' }, 'workflow permissions');

  const jobs = requireRecord(workflow.jobs, 'jobs');
  const jobNames = Object.keys(jobs).sort();
  if (jobNames.length !== 2 || jobNames[0] !== 'build' || jobNames[1] !== 'deploy') {
    fail('workflow must contain exactly the build and deploy jobs');
  }
  const build = requireRecord(jobs.build, 'build job');
  const deploy = requireRecord(jobs.deploy, 'deploy job');
  requireExactMapping(build.permissions, { contents: 'read' }, 'build permissions');
  requireExactMapping(
    deploy.permissions,
    { contents: 'read', pages: 'write', 'id-token': 'write' },
    'deploy permissions',
  );

  if (deploy.if !== EXPECTED_DEPLOY_CONDITION) {
    fail('deploy condition must be exact, manual, main-only, and confirmed');
  }
  if (deploy.needs !== 'build') {
    fail('deploy job must require the build job');
  }
  requireExactMapping(
    deploy.environment,
    {
      name: 'github-pages',
      url: '${{ steps.deployment.outputs.page_url }}',
    },
    'deploy environment',
  );

  const triggers = requireExactKeys(
    workflow.on,
    ['push', 'workflow_dispatch'],
    'workflow triggers',
  );
  const pushTrigger = requireExactKeys(
    triggers.push,
    ['branches'],
    'push trigger',
  );
  if (
    !Array.isArray(pushTrigger.branches) ||
    pushTrigger.branches.length !== 1 ||
    pushTrigger.branches[0] !== 'main'
  ) {
    fail('push trigger must contain exactly the main branch');
  }
  const workflowDispatch = requireExactKeys(
    triggers.workflow_dispatch,
    ['inputs'],
    'workflow_dispatch trigger',
  );
  const dispatchInputs = requireExactKeys(
    workflowDispatch.inputs,
    ['confirm_production_deploy'],
    'workflow_dispatch inputs',
  );
  const confirmation = requireExactKeys(
    dispatchInputs.confirm_production_deploy,
    ['description', 'required', 'default', 'type'],
    'production confirmation input',
  );
  if (
    confirmation.required !== true ||
    confirmation.default !== false ||
    confirmation.type !== 'boolean'
  ) {
    fail('production confirmation input must be required, boolean, and default false');
  }

  const deploySteps = deploy.steps;
  if (!Array.isArray(deploySteps) || deploySteps.length !== 2) {
    fail('deploy job must contain exactly configure-pages and deploy-pages');
  }
  if (
    !isRecord(deploySteps[0]) ||
    typeof deploySteps[0].uses !== 'string' ||
    !/^actions\/configure-pages@[0-9a-f]{40}$/i.test(deploySteps[0].uses)
  ) {
    fail('first deploy step must use an exact-SHA configure-pages action');
  }
  if (
    !isRecord(deploySteps[1]) ||
    deploySteps[1].id !== 'deployment' ||
    typeof deploySteps[1].uses !== 'string' ||
    !/^actions\/deploy-pages@[0-9a-f]{40}$/i.test(deploySteps[1].uses)
  ) {
    fail('second deploy step must use an exact-SHA deploy-pages action');
  }

  const findings = findPagesCapabilities(workflow);
  const counts = new Map();
  for (const finding of findings) {
    counts.set(finding.kind, (counts.get(finding.kind) ?? 0) + 1);
    if (finding.path[0] !== 'jobs' || finding.path[1] !== 'deploy') {
      fail(`${finding.kind} capability must be confined to the protected deploy job`);
    }
  }
  for (const kind of ['pages-write', 'configure-pages', 'deploy-pages']) {
    if (counts.get(kind) !== 1) {
      fail(`${kind} capability must occur exactly once`);
    }
  }
  for (const kind of ['write-all', 'actions-write', 'reusable-workflow']) {
    if (counts.has(kind)) {
      fail(`${kind} capability is forbidden`);
    }
  }

  verifySelfTests();
}

function verifyNoOtherPagesPublisher(workflowsDirectory, selectedWorkflow) {
  for (const entry of readdirSync(workflowsDirectory, { withFileTypes: true })) {
    if (!entry.isFile() || !/\.ya?ml$/.test(entry.name)) {
      continue;
    }
    const candidate = resolve(workflowsDirectory, entry.name);
    if (candidate === selectedWorkflow) {
      continue;
    }
    const workflow = parseWorkflowSource(
      readFileSync(candidate, 'utf8'),
      `workflow ${entry.name}`,
    );
    verifyReadOnlyWorkflowPermissions(workflow, `workflow ${entry.name}`);
    const findings = findPagesCapabilities(workflow);
    if (findings.length > 0) {
      fail(`unexpected Pages-capable workflow: ${entry.name}`);
    }
  }
}

if (process.argv.length > 3) {
  fail('usage: payment-v1-pages-deploy-gate.mjs [workflow-path]');
}
const workflowPath = resolve(
  process.argv[2] ??
    resolve(REPOSITORY_ROOT, '.github/workflows/deploy-web.yml'),
);
verifyDeployWorkflow(workflowPath);
if (process.argv[2] === undefined) {
  verifyNoOtherPagesPublisher(
    resolve(REPOSITORY_ROOT, '.github/workflows'),
    workflowPath,
  );
}
console.log(
  'pages-deploy-gate: PASS (semantic YAML, manual main-only, build-gated, least-privilege)',
);
