import { expect, type Locator, type Page, test } from '@playwright/test';

const CANARY_ADDRESS = '1D4HSHPJxoPLqiBNFNarz34dcWPLvpiaeb';
const QUERY_TIMEOUT = 10 * 60 * 1000;

test.skip(
  process.env.BPIR_PRODUCTION_CANARY !== '1',
  'Set BPIR_PRODUCTION_CANARY=1 to run live queries against production.',
);

// Each provider has its own page and strict session.  Parallel execution
// means a failure reports the remaining independent backends instead of
// serially skipping them; the production config caps this at two workers.
test.describe.configure({ mode: 'parallel' });

async function openBackend(page: Page, tabName: string): Promise<void> {
  await page.goto(`/?strict-canary=${Date.now()}`, { waitUntil: 'domcontentloaded' });
  const app = page.locator('#bitcoinPirApp');
  await expect(app).toHaveAttribute('data-module-readiness', 'ready');
  await expect(app).toHaveAttribute('aria-busy', 'false');
  const tab = page.getByRole('tab', { name: tabName, exact: true });
  await expect(tab).toBeVisible();
  await tab.click();
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
  await expect(results).toHaveAttribute('data-query-batch-state', 'complete', {
    timeout: QUERY_TIMEOUT,
  });
  await expect(results).toHaveAttribute('data-query-result-verification', 'verified');
  await expect(results).toContainText(CANARY_ADDRESS);
  return results;
}

async function expectVerified(...locators: Locator[]): Promise<void> {
  for (const locator of locators) {
    await expect(locator).toHaveAttribute('data-verification-state', 'verified', {
      timeout: QUERY_TIMEOUT,
    });
  }
}

async function expectTransportDisconnected(
  page: Page,
  statusSelector: string,
  connectSelector: string,
  disconnectSelector: string,
): Promise<void> {
  await expect(page.locator(statusSelector)).toHaveAttribute('data-transport-state', 'disconnected', {
    timeout: QUERY_TIMEOUT,
  });
  await expect(page.locator(connectSelector)).toBeEnabled();
  await expect(page.locator(disconnectSelector)).toBeDisabled();
}

test('DPF-PIR releases a strictly verified result and closes both transports', async ({ page }) => {
  await openBackend(page, 'DPF-PIR');
  await queryOnce(page, '#scriptPubkeys', '#queryBtn', '#resultsContainer');

  await expectVerified(
    page.locator('#dpfVerification0'),
    page.locator('#dpfVerification1'),
    page.locator('#dbProofBadge'),
  );
  await expectTransportDisconnected(page, '#status', '#connectBtn', '#disconnectBtn');
});

test('HarmonyPIR releases a strictly verified result and closes both transports', async ({ page }) => {
  await openBackend(page, 'HarmonyPIR');
  await queryOnce(page, '#hp-scriptPubkeys', '#hp-queryBtn', '#hp-resultsContainer');

  await expectVerified(
    page.locator('#hpVerificationHint'),
    page.locator('#hpVerificationQuery'),
    page.locator('#hp-dbProofBadge'),
  );
  await expectTransportDisconnected(page, '#hp-status', '#hp-connectBtn', '#hp-disconnectBtn');
});

test('OnionPIR releases a strictly verified result and closes its transport', async ({ page }) => {
  await openBackend(page, 'OnionPIR');
  await queryOnce(page, '#op-scriptPubkeys', '#op-queryBtn', '#op-resultsContainer');

  await expectVerified(
    page.locator('#onionVerification'),
    page.locator('#op-dbProofBadge'),
  );
  await expectTransportDisconnected(page, '#op-status', '#op-connectBtn', '#op-disconnectBtn');
});

test('ORAM TEE releases a strictly verified result and closes its transport', async ({ page }) => {
  await openBackend(page, 'ORAM TEE');
  await queryOnce(page, '#oram-scriptPubkeys', '#oram-queryBtn', '#oram-resultsContainer');

  await expectVerified(
    page.locator('#oramVerification'),
    page.locator('#oram-dbProofBadge'),
  );
  await expectTransportDisconnected(page, '#oram-status', '#oram-connectBtn', '#oram-disconnectBtn');
});
