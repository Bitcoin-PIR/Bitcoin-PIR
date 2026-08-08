import { expect, type Locator, type Page, test } from '@playwright/test';

const CANARY_ADDRESS = '1D4HSHPJxoPLqiBNFNarz34dcWPLvpiaeb';
const QUERY_TIMEOUT = 10 * 60 * 1000;

test.skip(
  process.env.BPIR_PRODUCTION_CANARY !== '1',
  'Set BPIR_PRODUCTION_CANARY=1 to run live queries against production.',
);

test.describe.configure({ mode: 'serial' });

async function openBackend(page: Page, tabName: string): Promise<void> {
  await page.goto(`/?strict-canary=${Date.now()}`, { waitUntil: 'domcontentloaded' });
  // The production bundle binds all backend/admission controls near the end
  // of its module. DOMContentLoaded can fire while it is still evaluating;
  // wait for its explicit, backend-independent interaction-ready state.
  const app = page.locator('#bitcoinPirApp');
  await expect(app).toHaveAttribute('data-module-readiness', 'ready');
  await expect(app).toHaveAttribute('aria-busy', 'false');
  await expect(page.getByRole('tab', { name: tabName, exact: true })).toBeVisible();
  await page.getByRole('tab', { name: tabName, exact: true }).click();
}

async function queryOnce(
  page: Page,
  inputSelector: string,
  buttonSelector: string,
  resultsSelector: string,
): Promise<Locator> {
  const button = page.locator(buttonSelector);
  const results = page.locator(resultsSelector);

  await page.locator(inputSelector).fill(CANARY_ADDRESS);
  await button.click();
  await expect(button).toHaveText('Querying…');
  await expect(button).toBeEnabled({ timeout: QUERY_TIMEOUT });
  await expectNoFatalLog(page);
  await expect(results).toContainText(CANARY_ADDRESS);
  return results;
}

async function expectVerifiedResult(results: Locator): Promise<void> {
  await expect(results.locator('.merkle-result-badge.verified')).toHaveText('✓ Verified', {
    timeout: QUERY_TIMEOUT,
  });
}

async function expectTornDown(
  page: Page,
  connectSelector: string,
  disconnectSelector: string,
): Promise<void> {
  await expect(page.locator(connectSelector)).toBeEnabled();
  await expect(page.locator(disconnectSelector)).toBeDisabled();
}

async function expectLogContains(page: Page, ...messages: string[]): Promise<void> {
  const log = page.locator('#log');
  for (const message of messages) {
    await expect(log).toContainText(message, { timeout: QUERY_TIMEOUT });
  }
}

async function expectNoFatalLog(page: Page): Promise<void> {
  const fatal = page.locator('#log').getByText(
    /(?:UNVERIFIED|chain validation failed|DB proof .* unavailable|ORAM source-binding proof check failed|WASM module required|query error:|batch error:|(?:connection|connect) failed:)/i,
  );
  await expect(fatal).toHaveCount(0);
}

test('DPF-PIR verifies both servers, the result, and tears down transport', async ({ page }) => {
  await openBackend(page, 'DPF-PIR');
  const results = await queryOnce(page, '#scriptPubkeys', '#queryBtn', '#resultsContainer');

  await expect(page.locator('#dpfVerification0')).toHaveText('YES');
  await expect(page.locator('#dpfVerification1')).toHaveText('YES');
  await expectVerifiedResult(results);
  await expectLogContains(
    page,
    'Upgraded to encrypted channel',
    'operator-endorsed identity verified (pir1)',
    'operator-endorsed identity verified (pir2)',
    'Bitcoin/MuHash anchor verified',
    'Batch complete: 1/1 found',
  );
  await expectTornDown(page, '#connectBtn', '#disconnectBtn');
  await expectNoFatalLog(page);
  await expectLogContains(
    page,
    'Disconnected',
  );
});

test('HarmonyPIR verifies both roles, the result, and preserves no socket', async ({ page }) => {
  await openBackend(page, 'HarmonyPIR');
  const results = await queryOnce(page, '#hp-scriptPubkeys', '#hp-queryBtn', '#hp-resultsContainer');

  await expect(page.locator('#hpVerificationHint')).toHaveText('YES');
  await expect(page.locator('#hpVerificationQuery')).toHaveText('YES');
  await expectVerifiedResult(results);
  await expectLogContains(
    page,
    'HarmonyPIR: upgraded to encrypted channel',
    'HarmonyPIR hint: operator-endorsed identity verified (pir1)',
    'HarmonyPIR query: operator-endorsed identity verified (pir2)',
    'HarmonyPIR batch complete: 1/1 found',
  );
  await expectTornDown(page, '#hp-connectBtn', '#hp-disconnectBtn');
  await expect(page.locator('#hp-status')).toContainText('Status: Disconnected');
  await expectNoFatalLog(page);
});

test('OnionPIR passes strict layout/tree-top preflight and verifies the result', async ({ page }) => {
  await openBackend(page, 'OnionPIR');
  const results = await queryOnce(page, '#op-scriptPubkeys', '#op-queryBtn', '#op-resultsContainer');

  await expect(page.locator('#onionVerification')).toHaveText('YES');
  await expectVerifiedResult(results);
  await expectLogContains(page, 'OnionPIR batch complete: 1/1 found');
  await expectTornDown(page, '#op-connectBtn', '#op-disconnectBtn');
  await expectNoFatalLog(page);
});

test('ORAM TEE verifies the runtime, completes a lookup, and disconnects', async ({ page }) => {
  await openBackend(page, 'ORAM TEE');
  await queryOnce(page, '#oram-scriptPubkeys', '#oram-queryBtn', '#oram-resultsContainer');

  await expect(page.locator('#oramVerification')).toHaveText('YES');
  await expectLogContains(
    page,
    'ORAM upgraded to encrypted channel',
    'ORAM: operator-endorsed identity verified (pir2)',
    'ORAM batch complete: 1/1 found',
  );
  await expectTornDown(page, '#oram-connectBtn', '#oram-disconnectBtn');
  await expect(page.locator('#oram-status')).toContainText('Status: Disconnected');
  await expectNoFatalLog(page);
  await expectLogContains(
    page,
    'ORAM: Disconnected',
  );
});
