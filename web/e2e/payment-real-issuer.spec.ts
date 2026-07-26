import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { expect, type Page, test } from '@playwright/test';

import type { RealIssuerHarnessFixtureV1 } from './payment-real-issuer-harness.js';

interface FixtureOfferV1 {
  method: string;
  offer_id: number;
}

interface FixtureScopeV1 {
  workload: string;
  scope_id: string;
  offers: FixtureOfferV1[];
}

interface FixtureProviderV1 {
  name: string;
  provider_id: string;
  policy_signing_pubkey: string;
  expected_payee_pubkey: string;
  policy_path: string;
  scopes: FixtureScopeV1[];
}

interface FixtureInventoryV1 {
  test_only: boolean;
  deterministic: boolean;
  funds_capable: boolean;
  network: string;
  providers: FixtureProviderV1[];
}

interface HarnessApi {
  initialize(fixture: RealIssuerHarnessFixtureV1): Promise<{
    providerIdHex: string;
    policyDigestHex: string;
    scopeIdHex: string;
    offerId: number;
    offerEndpoint: string;
  }>;
  startAcquisition(): Promise<{ recoveryId: string; invoice: string; status: string }>;
  settleAndPoll(): Promise<string>;
  claimWithLostResponse(): Promise<string>;
  resumeAndClaim(
    recoveryId: string,
  ): Promise<{ ok: true; count: number } | { ok: false; error: string }>;
  recoveryCount(): Promise<number>;
  capabilityCount(): Promise<number>;
  takeAndVerifyCapability(): Promise<number | null>;
  localStorageSnapshot(): Record<string, string>;
}

declare global {
  interface Window {
    paymentRealIssuerTest: HarnessApi;
    __paymentRealLocalStorageWrites?: Array<[string, string]>;
  }
}

test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    const writes: Array<[string, string]> = [];
    Object.defineProperty(window, '__paymentRealLocalStorageWrites', {
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

test('real WASM claims from a real no-funds issuer and exactly recovers a lost response',
  async ({ context }) => {
    const fixture = await loadFixture();
    const issuerOrigin = requiredEnvironment('BITCOINPIR_PAYMENT_REAL_ISSUER_ORIGIN');
    const claimBodies: Buffer[] = [];
    const claimStatuses: number[] = [];
    context.on('request', (request) => {
      const url = new URL(request.url());
      if (url.origin === issuerOrigin && url.pathname.endsWith('/claim')) {
        claimBodies.push(request.postDataBuffer() ?? Buffer.alloc(0));
      }
    });
    context.on('response', (response) => {
      const url = new URL(response.url());
      if (url.origin === issuerOrigin && url.pathname.endsWith('/claim')) {
        claimStatuses.push(response.status());
      }
    });

    const page = await readyPage(context.newPage());
    const accepted = await call(page, 'initialize', fixture);
    expect(accepted.providerIdHex).toBe(fixture.providerIdHex);
    expect(accepted.policyDigestHex).toMatch(/^[0-9a-f]{64}$/);
    expect(accepted.scopeIdHex).toBe(fixtureScopeId());
    expect(accepted.offerId).toBe(fixtureOfferId());
    expect(accepted.offerEndpoint).toBe('https://issuer-0.fixture.invalid');

    const started = await call(page, 'startAcquisition');
    expect(started.invoice).toMatch(/^lnbcrt1/);
    expect(started.status).toBe('invoice-open');
    await expect(call(page, 'settleAndPoll')).resolves.toBe('payment-settled');

    const lost = await call(page, 'claimWithLostResponse');
    expect(lost).toContain('simulated claim response loss after issuer commit');
    await expect(call(page, 'recoveryCount')).resolves.toBe(1);
    await expect(call(page, 'capabilityCount')).resolves.toBe(0);
    expect(await call(page, 'localStorageSnapshot')).toEqual({});
    expect(await page.evaluate(() => window.__paymentRealLocalStorageWrites ?? [])).toEqual([]);

    // Drop every in-memory policy/acquisition handle. Only encrypted IndexedDB
    // recovery state survives, then the same real claim is replayed.
    await page.reload();
    await waitReady(page);
    await call(page, 'initialize', fixture);
    await expect(call(page, 'resumeAndClaim', started.recoveryId)).resolves.toEqual({
      ok: true,
      count: 1,
    });

    expect(claimBodies).toHaveLength(2);
    expect(claimBodies[0].length).toBeGreaterThan(0);
    expect(claimBodies[1]).toEqual(claimBodies[0]);
    expect(claimStatuses).toEqual([200, 200]);
    await expect(call(page, 'recoveryCount')).resolves.toBe(0);
    await expect(call(page, 'capabilityCount')).resolves.toBe(1);
    const verifiedLength = await call(page, 'takeAndVerifyCapability');
    expect(verifiedLength).not.toBeNull();
    expect(verifiedLength).toBeGreaterThan(0);
    await expect(call(page, 'capabilityCount')).resolves.toBe(0);

    const storage = await call(page, 'localStorageSnapshot');
    const writes = await page.evaluate(() => window.__paymentRealLocalStorageWrites ?? []);
    expect(storage).toEqual({});
    expect(writes).toEqual([]);
    const browserResidue = JSON.stringify({ storage, writes });
    expect(browserResidue).not.toContain(started.invoice);
    expect(browserResidue).not.toContain(started.recoveryId);
    expect(browserResidue).not.toContain('bitcoin-address-query-sentinel');
    for (const claim of claimBodies) {
      expect(claim.includes(Buffer.from(started.invoice, 'utf8'))).toBe(false);
      expect(claim.includes(Buffer.from('bitcoin-address-query-sentinel', 'utf8'))).toBe(false);
    }
  });

let cachedFixture:
  | (RealIssuerHarnessFixtureV1 & { scopeId: string; offerId: number })
  | null = null;

async function loadFixture(): Promise<RealIssuerHarnessFixtureV1> {
  if (cachedFixture) return cachedFixture;
  const root = requiredEnvironment('BITCOINPIR_PAYMENT_REAL_FIXTURE');
  const inventory = JSON.parse(
    await readFile(join(root, 'fixture.json'), 'utf8'),
  ) as FixtureInventoryV1;
  if (!inventory.test_only
      || !inventory.deterministic
      || inventory.funds_capable
      || inventory.network !== 'regtest') {
    throw new Error('browser test refused a non-test or funds-capable fixture');
  }
  const provider = inventory.providers[0];
  const scope = provider?.scopes.find((candidate) => candidate.workload === 'dpf-evaluate-job-v1');
  const offer = scope?.offers.find((candidate) => candidate.method === 'bolt11');
  if (!provider || provider.name !== 'provider-0' || !scope || !offer) {
    throw new Error('browser test fixture is missing provider-0 DPF BOLT11 metadata');
  }
  cachedFixture = {
    providerIdHex: provider.provider_id,
    policySigningPubkeyHex: provider.policy_signing_pubkey,
    expectedPayeePubkeyHex: provider.expected_payee_pubkey,
    policyBytes: Array.from(await readFile(join(root, provider.policy_path))),
    issuerOrigin: requiredEnvironment('BITCOINPIR_PAYMENT_REAL_ISSUER_ORIGIN'),
    scopeId: scope.scope_id,
    offerId: offer.offer_id,
  };
  return cachedFixture;
}

function fixtureScopeId(): string {
  if (!cachedFixture) throw new Error('fixture was not loaded');
  return cachedFixture.scopeId;
}

function fixtureOfferId(): number {
  if (!cachedFixture) throw new Error('fixture was not loaded');
  return cachedFixture.offerId;
}

async function readyPage(pagePromise: Promise<Page>): Promise<Page> {
  const page = await pagePromise;
  await page.goto('/e2e/payment-real-issuer.html');
  await waitReady(page);
  return page;
}

async function waitReady(page: Page): Promise<void> {
  await expect(page.locator('html')).toHaveAttribute('data-payment-real-issuer-ready', 'true');
}

function call<K extends keyof HarnessApi>(
  page: Page,
  method: K,
  ...args: HarnessApi[K] extends (...values: infer P) => unknown ? P : never
): Promise<HarnessApi[K] extends (...values: never[]) => infer R ? Awaited<R> : never> {
  return page.evaluate(
    async ({ method: name, args: values }) => {
      const fn = window.paymentRealIssuerTest[name] as (...items: unknown[]) => unknown;
      return fn(...values);
    },
    { method, args },
  ) as Promise<HarnessApi[K] extends (...values: never[]) => infer R ? Awaited<R> : never>;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is unavailable; real issuer global setup did not run`);
  return value;
}
