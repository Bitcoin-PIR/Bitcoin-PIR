import { readFileSync } from 'node:fs';

function requireBefore(source, token, before, description) {
  const index = source.indexOf(token);
  if (index < 0) throw new Error(`missing ${description}`);
  if (index >= before) throw new Error(`${description} must precede module readiness`);
  return index;
}

const indexHtmlUrl = new URL('../index.html', import.meta.url);
const strictCanaryUrl = new URL('../e2e/strict-production.spec.ts', import.meta.url);
const indexHtml = readFileSync(indexHtmlUrl, 'utf8');
const strictCanary = readFileSync(strictCanaryUrl, 'utf8');
const moduleSource = indexHtml.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1];

if (!moduleSource) throw new Error('index.html has no application module');
if (!/id="bitcoinPirApp"[\s\S]*aria-busy="true"[\s\S]*data-module-readiness="initializing"/.test(indexHtml)) {
  throw new Error('application root has no initializing readiness state');
}

const readinessIndex = moduleSource.indexOf(
  "bitcoinPirApp?.setAttribute('data-module-readiness', 'ready')",
);
if (readinessIndex < 0
    || !moduleSource.includes("bitcoinPirApp?.setAttribute('aria-busy', 'false')")) {
  throw new Error('application module never publishes an interaction-ready state');
}

for (const [token, description] of [
  ["document.querySelectorAll('.tab-btn').forEach(btn =>", 'backend tab listeners'],
  ["document.getElementById('connectBtn').addEventListener('click', runDpfQueryOnce)", 'DPF query listener'],
  ["document.getElementById('op-connectBtn').addEventListener('click', runOnionQueryOnce)", 'OnionPIR query listener'],
  ["document.getElementById('hp-connectBtn').addEventListener('click', runHarmonyQueryOnce)", 'HarmonyPIR query listener'],
  ["document.getElementById('oram-connectBtn').addEventListener('click', runOramQueryOnce)", 'ORAM query listener'],
]) {
  requireBefore(moduleSource, token, readinessIndex, description);
}

const openBackend = strictCanary.match(
  /async function openBackend[\s\S]*?\n}\n\nasync function queryOnce/,
)?.[0];
if (!openBackend) throw new Error('strict production canary has no openBackend helper');
if (/#log|ORAM source|source-binding|toContainText/.test(openBackend)) {
  throw new Error('openBackend must not depend on a backend proof log');
}
if (!/locator\('#bitcoinPirApp'\)[\s\S]*data-module-readiness', 'ready'[\s\S]*aria-busy', 'false'/.test(openBackend)) {
  throw new Error('openBackend must wait for the explicit interaction-ready state');
}

const noFatalLog = strictCanary.match(
  /async function expectNoFatalLog[\s\S]*?\n}\n\n(?:test|async function)/,
)?.[0];
if (!noFatalLog) throw new Error('strict production canary has no expectNoFatalLog helper');
if (!/locator\('#log \.log-entry'\)\.filter\(\{ hasText: fatalPattern \}\)/.test(noFatalLog)) {
  throw new Error('fatal canary matching must stay scoped to individual log entries');
}
if (/locator\('#log'\)\.getByText/.test(noFatalLog)) {
  throw new Error('fatal canary matching must not aggregate text across the log container');
}

process.stdout.write(
  'verified strict production canary readiness and line-scoped fatal log matching\n',
);
