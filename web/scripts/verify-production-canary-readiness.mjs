import { readFileSync } from 'node:fs';

function requireBefore(source, token, before, description) {
  const index = source.indexOf(token);
  if (index < 0) throw new Error(`missing ${description}`);
  if (index >= before) throw new Error(`${description} must precede module readiness`);
  return index;
}

function requireInOrder(source, tokens, description) {
  let cursor = -1;
  for (const token of tokens) {
    const index = source.indexOf(token, cursor + 1);
    if (index < 0) throw new Error(`missing ${description}: ${token}`);
    cursor = index;
  }
}

const indexHtmlUrl = new URL('../index.html', import.meta.url);
const strictCanaryUrl = new URL('../e2e/strict-production.spec.ts', import.meta.url);
const productionConfigUrl = new URL('../playwright.production.config.ts', import.meta.url);
const workflowUrl = new URL('../../.github/workflows/web-strict-production-canary.yml', import.meta.url);
const indexHtml = readFileSync(indexHtmlUrl, 'utf8');
const strictCanary = readFileSync(strictCanaryUrl, 'utf8');
const productionConfig = readFileSync(productionConfigUrl, 'utf8');
const workflow = readFileSync(workflowUrl, 'utf8');
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

for (const id of [
  'resultsContainer',
  'op-resultsContainer',
  'hp-resultsContainer',
  'oram-resultsContainer',
]) {
  if (!new RegExp(`id="${id}"[^>]*data-query-batch-state="idle"`).test(indexHtml)) {
    throw new Error(`${id} must expose its initial semantic batch state`);
  }
}
for (const id of ['status', 'op-status', 'hp-status', 'oram-status']) {
  if (!new RegExp(`id="${id}"[^>]*data-transport-state="disconnected"`).test(indexHtml)) {
    throw new Error(`${id} must expose its initial transport state`);
  }
}
const publishDisconnect = moduleSource.slice(
  moduleSource.indexOf('function publishTransportDisconnected'),
  moduleSource.indexOf('// Slice 3: persistent attestation badge'),
);
if (!publishDisconnect.includes("dataset.transportState = 'disconnected'")) {
  throw new Error('the transport disconnect publisher must expose a semantic state');
}
for (const statusId of ['status', 'op-status', 'oram-status']) {
  if (!moduleSource.includes(`publishTransportDisconnected('${statusId}')`)) {
    throw new Error(`${statusId} must publish explicit disconnect state during teardown`);
  }
}

for (const [start, end, description] of [
  ['function renderBasicVerification', 'function resetBasicVerification', 'runtime/provider verification'],
  ['function opSetDataIntegrity', 'function opUpdateDataIntegritySummary', 'Onion database verification'],
  ['function renderDatabaseProofBadge', 'function renderBitcoinAnchorBadge', 'database proof verification'],
]) {
  const section = moduleSource.slice(moduleSource.indexOf(start), moduleSource.indexOf(end));
  if (!section.includes('dataset.verificationState')) {
    throw new Error(`${description} has no stable verification-state contract`);
  }
}

const batchContract = moduleSource.slice(
  moduleSource.indexOf('function beginQueryBatch'),
  moduleSource.indexOf('function waitForResultPaint'),
);
for (const token of [
  "dataset.queryBatchState = 'running'",
  "dataset.queryResultVerification = 'verified'",
  "dataset.queryBatchState = 'complete'",
  "dataset.queryBatchState = 'failed'",
]) {
  if (!batchContract.includes(token)) {
    throw new Error(`missing query batch semantic transition: ${token}`);
  }
}

for (const [start, end, container] of [
  ['async function queryUtxos()', 'async function runDpfQueryOnce()', 'resultsContainer'],
  ['async function opQueryUtxos()', 'async function runOnionQueryOnce()', 'resultsContainer'],
  ['async function hpQueryUtxos()', 'async function runHarmonyQueryOnce()', 'resultsContainer'],
  ['async function oramQueryUtxos()', 'async function runOramQueryOnce()', 'resultsContainer'],
]) {
  const query = moduleSource.slice(moduleSource.indexOf(start), moduleSource.indexOf(end));
  requireInOrder(query, [
    `beginQueryBatch(${container});`,
    `completeVerifiedQueryBatch(${container});`,
  ], `${start} success transition`);
  if (!query.includes(`failQueryBatch(${container});`)) {
    throw new Error(`${start} must not leave a failed batch as verified`);
  }
}

const oramConnect = moduleSource.slice(
  moduleSource.indexOf('async function oramConnect'),
  moduleSource.indexOf('function oramDisconnect'),
);
for (const strictToken of [
  'await oramClient.connect();',
  "sourceDbStatus?.state !== 'verified'",
  'sourceDbStatus.proof',
  'manifestRootHex',
]) {
  if (!oramConnect.includes(strictToken)) {
    throw new Error(`ORAM connection lost its strict live admission prerequisite: ${strictToken}`);
  }
}
if (oramConnect.includes('await verifyAndRenderOramSourceProofBadge(')) {
  throw new Error('ORAM source proof must not block a strict live connection');
}
if (!oramConnect.includes('void verifyAndRenderOramSourceProofBadge(')
    || !oramConnect.includes('informational source proof unavailable')
    || !oramConnect.includes("state: 'unavailable'")) {
  throw new Error('ORAM source-proof rejection must be rendered as informational only');
}
const sourceProofStart = oramConnect.indexOf('void verifyAndRenderOramSourceProofBadge(');
const sourceProofEnd = oramConnect.indexOf('\n            } catch (error) {', sourceProofStart);
const sourceProofTask = oramConnect.slice(sourceProofStart, sourceProofEnd);
if (sourceProofEnd < 0 || sourceProofTask.includes('oramClient = null')) {
  throw new Error('ORAM source-proof rejection must not clear the strict live client');
}
if (!sourceProofTask.includes('sourceProofIsCurrent')
    || !sourceProofTask.includes('if (!sourceProofIsCurrent()) return;')) {
  throw new Error('ORAM source-proof completion must reject a stale client or db selection');
}
const sourceProofHelper = moduleSource.slice(
  moduleSource.indexOf('async function verifyAndRenderOramSourceProofBadge'),
  moduleSource.indexOf('function setProgress'),
);
if ((sourceProofHelper.match(/if \(!isCurrent\(\)\) return;/g) ?? []).length < 2) {
  throw new Error('ORAM source-proof helper must guard both pre-fetch and post-fetch rendering');
}
if (oramConnect.includes('pin => pin.dbId === 0')
    || !oramConnect.includes('pin => pin.dbId === selectedDbId')) {
  throw new Error('ORAM source proof must select the production pin for the chosen db');
}
if (!moduleSource.includes('const preferredDbId = Number.parseInt(select.value, 10);')
    || !moduleSource.includes('if (db.dbId === preferredDbId) opt.selected = true;')) {
  throw new Error('ORAM catalog refresh must preserve the requested db before admission');
}
if (!moduleSource.includes("select.options.length > 1 ? 'block' : 'none'")
    || !moduleSource.includes('renderOramSourceProofWaitingForDb(selectedDbId);')) {
  throw new Error('ORAM disconnect must expose the verified catalog for a new exact-db admission');
}

if (/\bschedule\s*:/.test(workflow) || !/^\s*workflow_dispatch:\s*$/m.test(workflow)) {
  throw new Error('live browser canary must be manual-only');
}
if (!/fullyParallel:\s*true/.test(productionConfig) || !/workers:\s*2/.test(productionConfig)) {
  throw new Error('production browser canary must run independent tests with at most two workers');
}
if (!/test\.describe\.configure\(\{ mode: 'parallel' \}\)/.test(strictCanary)) {
  throw new Error('strict production canary must not serially suppress other backends');
}
if ((strictCanary.match(/\ntest\('/g) ?? []).length !== 4) {
  throw new Error('strict production canary must retain one independent test per backend');
}
for (const forbidden of [
  '#log',
  'expectLogContains',
  'expectNoFatalLog',
  'fatalPattern',
  'operator-endorsed identity verified',
  'source-binding',
  'sourceProofBadge',
]) {
  if (strictCanary.includes(forbidden)) {
    throw new Error(`strict production canary must not gate on diagnostics: ${forbidden}`);
  }
}
for (const required of [
  "data-query-batch-state', 'complete'",
  "data-query-result-verification', 'verified'",
  "data-verification-state', 'verified'",
  "data-transport-state', 'disconnected'",
]) {
  if (!strictCanary.includes(required)) {
    throw new Error(`strict production canary does not require semantic state: ${required}`);
  }
}

process.stdout.write(
  'verified strict production canary semantic DOM contract and manual-only policy\n',
);
