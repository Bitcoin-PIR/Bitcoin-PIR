import { chmod, lstat, open, readFile } from 'node:fs/promises';

import { expect, type Page, test } from '@playwright/test';

import type { CdkCashuBrowserFixtureV1 } from './payment-cdk-cashu-harness.js';

interface HarnessApiV1 {
  importRealCdkToken(fixture: CdkCashuBrowserFixtureV1): Promise<{
    providerIdHex: string;
    policyDigestHex: string;
    scopeIdHex: string;
    offerId: number;
    canonicalSpend: number[];
    originalTokenRejection: string;
    capabilityCountBeforeTake: number;
    capabilityCountAfterTake: number;
    localStorage: Record<string, string>;
  }>;
}

test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    const writes: Array<[string, string]> = [];
    Object.defineProperty(window, '__paymentCdkLocalStorageWrites', {
      configurable: false,
      value: writes,
    });
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function setItem(key: string, value: string): void {
      if (this === window.localStorage) writes.push([String(key), String(value)]);
      original.call(this, key, value);
    };
  });
});

test('CDK 0.17.3 cashuB imports through generated WASM and retires from the encrypted vault',
  async ({ page }) => {
    const fixture = await loadOwnerOnlyFixture();
    try {
      await readyPage(page);
      const result = await page.evaluate(
        (input) => (window.paymentCdkCashuTest as HarnessApiV1).importRealCdkToken(input),
        fixture,
      );
      try {
        expect(result.providerIdHex).toBe(fixture.providerIdHex);
        expect(result.policyDigestHex).toMatch(/^[0-9a-f]{64}$/);
        expect(result.scopeIdHex).toMatch(/^[0-9a-f]{64}$/);
        expect(result.offerId).toBe(17);
        expect(result.originalTokenRejection).toContain('mint does not match the signed manifest');
        expect(result.capabilityCountBeforeTake).toBe(1);
        expect(result.capabilityCountAfterTake).toBe(0);
        expect(result.canonicalSpend.length).toBeGreaterThan(0);
        expect(result.canonicalSpend.length).toBeLessThanOrEqual(12 * 1024);
        expect(result.localStorage).toEqual({});
        expect(await page.evaluate(() => window.__paymentCdkLocalStorageWrites ?? [])).toEqual([]);

        await writeOwnerOnlySpend(Uint8Array.from(result.canonicalSpend));
      } finally {
        result.canonicalSpend.fill(0);
      }
    } finally {
      fixture.policyBytes.fill(0);
      fixture.originalToken = '';
      fixture.browserToken = '';
    }
  });

async function loadOwnerOnlyFixture(): Promise<CdkCashuBrowserFixtureV1> {
  const fixturePath = requiredEnvironment('BITCOINPIR_CDK_BROWSER_FIXTURE_FILE');
  await assertOwnerOnlyRegularFile(fixturePath);
  const parsed = JSON.parse(await readFile(fixturePath, 'utf8')) as CdkCashuBrowserFixtureV1;
  return parsed;
}

async function writeOwnerOnlySpend(spend: Uint8Array): Promise<void> {
  try {
    if (spend.length === 0 || spend.length > 12 * 1024) {
      throw new Error('browser returned an invalid canonical spend length');
    }
    const path = requiredEnvironment('BITCOINPIR_CDK_BROWSER_SPEND_FILE');
    const file = await open(path, 'wx', 0o600);
    try {
      await file.writeFile(spend);
      await file.sync();
    } finally {
      await file.close();
    }
    await chmod(path, 0o600);
    await assertOwnerOnlyRegularFile(path);
  } finally {
    spend.fill(0);
  }
}

async function assertOwnerOnlyRegularFile(path: string): Promise<void> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error('Cashu browser fixture must be an owner-only regular file');
  }
}

async function readyPage(page: Page): Promise<void> {
  await page.goto('/e2e/payment-cdk-cashu.html');
  await page.waitForFunction(
    () => document.documentElement.dataset.paymentCdkCashuReady === 'true',
  );
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
