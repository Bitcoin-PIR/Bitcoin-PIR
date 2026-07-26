import { expect, type BrowserContext, type Page, test } from '@playwright/test';

const CT_DELEGATION =
  'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1';
const CT_QUOTE = 'application/vnd.bitcoinpir.bolt11-quote-v1';
const CT_ISSUANCE = 'application/vnd.bitcoinpir.credential-issuance-response-v1';

interface HarnessApi {
  putCapability(payload: number[]): Promise<void>;
  countCapabilities(): Promise<number>;
  putArcCredential(remaining: number): Promise<void>;
  countArcCredentials(): Promise<number>;
  advanceArcCredential(): Promise<number[] | null>;
  takeCapability(): Promise<number[] | null>;
  rejectReservedCapability(): Promise<string>;
  startSettledAcquisition(): Promise<{
    recoveryId: string;
    invoice: string;
    status: string;
  }>;
  claimActive(): Promise<{ ok: true; count: number } | { ok: false; error: string }>;
  resumeAndClaim(
    recoveryId: string,
  ): Promise<{ ok: true; count: number } | { ok: false; error: string }>;
  recoveryCount(): Promise<number>;
  localStorageSnapshot(): Record<string, string>;
}

declare global {
  interface Window {
    paymentVaultTest: HarnessApi;
    __paymentLocalStorageWrites?: Array<[string, string]>;
  }
}

test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    const writes: Array<[string, string]> = [];
    Object.defineProperty(window, '__paymentLocalStorageWrites', {
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

test('one browser capability cannot be taken by two tabs', async ({ context }) => {
  const [first, second] = await twoReadyTabs(context);

  for (let value = 1; value <= 16; value += 1) {
    await call(first, 'putCapability', [value]);
    const results = await Promise.all([
      call(first, 'takeCapability'),
      call(second, 'takeCapability'),
    ]);
    expect(results.filter((result) => result !== null)).toEqual([[value]]);
    await expect(call(first, 'countCapabilities')).resolves.toBe(0);
  }
});

test('ARC presentation state advances before release across tabs', async ({ context }) => {
  const [first, second] = await twoReadyTabs(context);
  await call(first, 'putArcCredential', 2);

  const presentations = await Promise.all([
    call(first, 'advanceArcCredential'),
    call(second, 'advanceArcCredential'),
  ]);
  expect(presentations.sort((left, right) => (right?.[0] ?? 0) - (left?.[0] ?? 0)))
    .toEqual([[2], [1]]);
  await expect(call(first, 'countArcCredentials')).resolves.toBe(0);
  await expect(call(second, 'advanceArcCredential')).resolves.toBeNull();
});

test('validation failure releases the local reservation; success commits deletion before release',
  async ({ context }) => {
    const [first, second] = await twoReadyTabs(context);
    await call(first, 'putCapability', [7, 8]);

    await expect(call(first, 'rejectReservedCapability')).resolves.toContain(
      'rejected before commit',
    );
    await expect(call(second, 'countCapabilities')).resolves.toBe(1);

    await expect(call(first, 'takeCapability')).resolves.toEqual([7, 8]);
    await expect(call(second, 'countCapabilities')).resolves.toBe(0);
    await expect(call(second, 'takeCapability')).resolves.toBeNull();
  });

test('paid claim response loss replays exactly once across tabs without localStorage linkage',
  async ({ context }) => {
    const claimBodies: Buffer[] = [];
    let claimRequests = 0;
    await context.route('**/v1/**', async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      if (pathname === '/v1/quote-keys/current') {
        await route.fulfill(binaryResponse([1], CT_DELEGATION));
        return;
      }
      if (pathname === '/v1/quotes/bolt11') {
        await route.fulfill(binaryResponse([2], CT_QUOTE));
        return;
      }
      if (pathname.endsWith('/status')) {
        await route.fulfill(binaryResponse([3], CT_QUOTE));
        return;
      }
      if (pathname.endsWith('/claim')) {
        claimRequests += 1;
        claimBodies.push(request.postDataBuffer() ?? Buffer.alloc(0));
        if (claimRequests === 1) {
          // Simulate: issuer durably committed, but its HTTP response was lost.
          await route.abort('connectionreset');
        } else {
          await route.fulfill(binaryResponse([4], CT_ISSUANCE));
        }
        return;
      }
      await route.abort('blockedbyclient');
    });

    const first = await readyTab(context);
    const started = await call(first, 'startSettledAcquisition');
    expect(started.status).toBe('payment-settled');
    expect(started.invoice).toContain('lnbc1');

    const lost = await call(first, 'claimActive');
    expect(lost).toMatchObject({ ok: false });
    await expect(call(first, 'recoveryCount')).resolves.toBe(1);
    expect(await call(first, 'localStorageSnapshot')).toEqual({});
    expect(await first.evaluate(() => window.__paymentLocalStorageWrites ?? [])).toEqual([]);

    // A page close/reopen loses all in-memory controller state. Only the
    // encrypted IndexedDB recovery record survives.
    await first.reload();
    await waitReady(first);
    const second = await readyTab(context);
    const recovered = await Promise.all([
      call(first, 'resumeAndClaim', started.recoveryId),
      call(second, 'resumeAndClaim', started.recoveryId),
    ]);
    expect(recovered.filter((result) => result.ok)).toEqual([{ ok: true, count: 1 }]);
    expect(recovered.filter((result) => !result.ok)).toHaveLength(1);

    expect(claimRequests).toBe(2);
    expect(claimBodies).toHaveLength(2);
    expect(claimBodies[1]).toEqual(claimBodies[0]);
    await expect(call(first, 'recoveryCount')).resolves.toBe(0);
    await expect(call(second, 'countCapabilities')).resolves.toBe(1);

    const spendRace = await Promise.all([
      call(first, 'takeCapability'),
      call(second, 'takeCapability'),
    ]);
    expect(spendRace.filter((result) => result !== null)).toEqual([[10, 11]]);

    for (const page of [first, second]) {
      const storage = await call(page, 'localStorageSnapshot');
      const writes = await page.evaluate(() => window.__paymentLocalStorageWrites ?? []);
      expect(storage).toEqual({});
      expect(writes).toEqual([]);
      expect(JSON.stringify({ storage, writes })).not.toContain(started.invoice);
      expect(JSON.stringify({ storage, writes })).not.toContain(started.recoveryId);
      expect(JSON.stringify({ storage, writes })).not.toContain('bitcoin-address-query-sentinel');
    }
  });

async function twoReadyTabs(context: BrowserContext): Promise<[Page, Page]> {
  const first = await readyTab(context);
  const second = await readyTab(context);
  return [first, second];
}

async function readyTab(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto('/e2e/payment-vault.html');
  await waitReady(page);
  return page;
}

async function waitReady(page: Page): Promise<void> {
  await expect(page.locator('html')).toHaveAttribute('data-payment-vault-ready', 'true');
}

function call<K extends keyof HarnessApi>(
  page: Page,
  method: K,
  ...args: HarnessApi[K] extends (...values: infer P) => unknown ? P : never
): Promise<HarnessApi[K] extends (...values: never[]) => infer R ? Awaited<R> : never> {
  return page.evaluate(
    async ({ method: name, args: values }) => {
      const fn = window.paymentVaultTest[name] as (...items: unknown[]) => unknown;
      return fn(...values);
    },
    { method, args },
  ) as Promise<HarnessApi[K] extends (...values: never[]) => infer R ? Awaited<R> : never>;
}

function binaryResponse(bytes: number[], contentType: string): {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
} {
  return {
    status: 200,
    headers: { 'Content-Type': contentType },
    body: Buffer.from(bytes),
  };
}
