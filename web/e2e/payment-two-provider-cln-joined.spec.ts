import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { expect, type BrowserContext, type Page, test } from '@playwright/test';

import type {
  PaymentTwoProviderFixtureV1,
  PaymentTwoProviderVariantV1,
} from './payment-two-provider.global-setup.js';

interface CapabilityBindingV1 {
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  scheme: string;
}

interface HarnessApi {
  initialize(fixture: PaymentTwoProviderFixtureV1): Promise<{
    secureChannel: true;
    attestationBoundary: [string, string];
    databaseProofInstalled: true;
    providers: Array<{
      providerIdHex: string;
      policyDigestHex: string;
      issuerOrigin: string;
      payeePubkeyHex: string;
    }>;
  }>;
  selectVariant(variant: PaymentTwoProviderVariantV1): Array<{
    index: 0 | 1;
    authorization: string;
    acquisition: string;
    deploymentStatus: string;
  }>;
  acquireLeg(index: 0 | 1): Promise<{
    invoice: string | null;
    count: number;
    binding: CapabilityBindingV1 | null;
  }>;
  startPaidLeg(index: 0 | 1): Promise<{
    recoveryId: string;
    invoice: string;
    binding: CapabilityBindingV1;
  }>;
  finishPaidLeg(index: 0 | 1, recoveryId: string): Promise<{
    count: number;
    binding: CapabilityBindingV1;
  }>;
  authorizeLeg(index: 0 | 1): Promise<{ scopeIdHex: string; enforcedProfile: number }>;
  preflightAndQuery(): Promise<{
    preflightComplete: true;
    explicitMerkleVerified: true;
    entryCount: number;
    totalBalanceSats: string;
    isWhale: boolean;
  }>;
  replaySpentCapability(index: 0 | 1): Promise<string>;
  replayFreeQuota(index: 0 | 1): Promise<string>;
  capabilityCount(index: 0 | 1): Promise<number>;
  retainedReplayProofContains(index: 0 | 1, needle: number[]): boolean;
  localStorageSnapshot(): Record<string, string>;
}

test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    const writes: Array<[string, string]> = [];
    Object.defineProperty(window, '__paymentTwoProviderLocalStorageWrites', {
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

test('real routed CLN buys direct, BAT and experimental ARC before verified provider queries',
  async ({ context }) => {
    const fixture = loadFixture();
    const providerFrames = new Map<string, Buffer[]>();
    const claimBodies: Buffer[] = [];
    const issuerPaths = captureIssuerRequests(context, fixture, claimBodies);
    const paymentPreimages: Buffer[] = [];
    const invoices: string[] = [];
    const page = await readyPage(context, fixture, providerFrames);

    try {
      const initialized = await call(page, 'initialize', fixture);
      expect(initialized.secureChannel).toBe(true);
      expect(initialized.attestationBoundary).toEqual(['noSevHost', 'noSevHost']);
      expect(initialized.databaseProofInstalled).toBe(true);
      expect(initialized.providers).toHaveLength(2);
      expect(initialized.providers[0].providerIdHex).not.toBe(
        initialized.providers[1].providerIdHex,
      );
      expect(initialized.providers[0].policyDigestHex).not.toBe(
        initialized.providers[1].policyDigestHex,
      );
      expect(initialized.providers[0].issuerOrigin).not.toBe(
        initialized.providers[1].issuerOrigin,
      );
      // This disposable topology intentionally has two independent credential
      // issuers settle to one CLN invoice node. It proves a shared settlement
      // service option, not independent Lightning-operator privacy.
      expect(initialized.providers[0].payeePubkeyHex).toBe(
        initialized.providers[1].payeePubkeyHex,
      );
      expect(fixture.providers[0].issuerIdHex).not.toBe(fixture.providers[1].issuerIdHex);

      const directBat = await call(page, 'selectVariant', 'direct-bat');
      expect(directBat.map((offer) => offer.authorization)).toEqual([
        'bolt11-direct-receipt',
        'cashu-bat',
      ]);
      const direct = await startPayAndFinish(page, 0, paymentPreimages);
      const bat = await startPayAndFinish(page, 1, paymentPreimages);
      invoices.push(direct.invoice, bat.invoice);
      if (direct.invoice === bat.invoice) {
        throw new Error('independent provider acquisitions returned one repeated invoice');
      }
      expect(direct.binding.scheme).toBe('bolt11-direct-receipt');
      expect(bat.binding.scheme).toBe('cashu-bat');
      await expect(call(page, 'capabilityCount', 0)).resolves.toBe(1);
      await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);

      await authorizeBoth(page, fixture);
      await expect(call(page, 'capabilityCount', 0)).resolves.toBe(0);
      await expect(call(page, 'capabilityCount', 1)).resolves.toBe(0);
      await expectVerifiedEmptyQuery(page);
      await expect(call(page, 'replaySpentCapability', 0)).resolves.toMatch(/invalid-or-spent/i);
      await expect(call(page, 'replaySpentCapability', 1)).resolves.toMatch(/invalid-or-spent/i);

      await call(page, 'initialize', fixture);
      const freeArc = await call(page, 'selectVariant', 'free-arc-experimental');
      expect(freeArc.map((offer) => [offer.authorization, offer.deploymentStatus])).toEqual([
        ['free', 'stable'],
        ['arc-experimental', 'experimental'],
      ]);
      const providerZeroRequestsBeforeFree =
        issuerPaths.get(fixture.providers[0].issuerOrigin)?.length ?? -1;
      await expect(call(page, 'acquireLeg', 0)).resolves.toEqual({
        invoice: null,
        count: 0,
        binding: null,
      });
      expect(issuerPaths.get(fixture.providers[0].issuerOrigin)?.length).toBe(
        providerZeroRequestsBeforeFree,
      );

      const arc = await startPayAndFinish(page, 1, paymentPreimages);
      invoices.push(arc.invoice);
      expect(arc.binding.scheme).toBe('arc-experimental');
      await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);
      await authorizeBoth(page, fixture);
      // The fixture issues one multi-presentation ARC credential; consuming a
      // presentation advances its durable browser state rather than deleting it.
      await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);
      await expectVerifiedEmptyQuery(page);
      await expect(call(page, 'replayFreeQuota', 0)).resolves.toMatch(/server-busy/i);
      await expect(call(page, 'replaySpentCapability', 1)).resolves.toMatch(/invalid-or-spent/i);

      expect(new Set(invoices).size).toBe(3);
      // A whole-second issuer lifecycle fence may conservatively return 503
      // once before the byte-identical idempotent claim succeeds.
      expect(claimBodies.length).toBeGreaterThanOrEqual(3);
      const allIssuerPaths = Array.from(issuerPaths.values()).flat();
      expect(allIssuerPaths).not.toContain('/__test/fake/settle');
      for (const provider of fixture.providers) {
        const paths = issuerPaths.get(provider.issuerOrigin) ?? [];
        expect(paths).toContain('/v1/quotes/bolt11');
        expect(paths.some((path) => /^\/v1\/quotes\/[0-9a-f]{64}\/claim$/.test(path))).toBe(true);
      }
      const hashes = invoices.map(bolt11PaymentHash);
      expect(new Set(hashes.map((hash) => hash.toString('hex'))).size).toBe(3);
      const queryScriptHash = Buffer.alloc(20, 0x42);
      const needles = [
        ...invoices.map((invoice) => Buffer.from(invoice, 'utf8')),
        ...hashes,
        ...paymentPreimages,
        queryScriptHash,
      ];
      for (const provider of [0, 1] as const) {
        for (const needle of needles) {
          await expect(call(
            page,
            'retainedReplayProofContains',
            provider,
            Array.from(needle),
          )).resolves.toBe(false);
        }
      }
      await assertProviderObservationsExclude(fixture, providerFrames, needles);
      for (const claim of claimBodies) {
        for (const needle of needles) expect(claim.includes(needle)).toBe(false);
      }
      expect(await call(page, 'localStorageSnapshot')).toEqual({});
      expect(await page.evaluate(
        () => window.__paymentTwoProviderLocalStorageWrites ?? [],
      )).toEqual([]);
    } finally {
      for (const preimage of paymentPreimages) preimage.fill(0);
      paymentPreimages.length = 0;
    }
  });

async function startPayAndFinish(
  page: Page,
  index: 0 | 1,
  paymentPreimages: Buffer[],
): Promise<{ invoice: string; binding: CapabilityBindingV1 }> {
  const started = await call(page, 'startPaidLeg', index);
  if (!/^lnbcrt[0-9]+[munp]?1/.test(started.invoice)) {
    throw new Error(`provider ${index} returned a non-regtest BOLT11 invoice`);
  }
  const paymentHash = bolt11PaymentHash(started.invoice);
  const preimage = payClnRegtestInvoice(started.invoice);
  if (!createHash('sha256').update(preimage).digest().equals(paymentHash)) {
    preimage.fill(0);
    throw new Error('local CLN payer preimage did not match the signed invoice payment hash');
  }
  paymentPreimages.push(preimage);
  await waitPastCurrentUnixSecond();
  const finished = await call(page, 'finishPaidLeg', index, started.recoveryId);
  expect(finished.count).toBe(1);
  expect(finished.binding).toEqual(started.binding);
  return { invoice: started.invoice, binding: finished.binding };
}

async function waitPastCurrentUnixSecond(): Promise<void> {
  const paidSecond = Math.floor(Date.now() / 1_000);
  const deadline = Date.now() + 2_500;
  while (Math.floor(Date.now() / 1_000) <= paidSecond) {
    if (Date.now() >= deadline) throw new Error('wall clock did not advance after CLN payment');
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
}

async function authorizeBoth(page: Page, fixture: PaymentTwoProviderFixtureV1): Promise<void> {
  for (const index of [0, 1] as const) {
    await expect(call(page, 'authorizeLeg', index)).resolves.toEqual({
      scopeIdHex: fixture.providers[index].scopeIdHex,
      enforcedProfile: fixture.providers[index].entitlementProfile,
    });
  }
}

async function expectVerifiedEmptyQuery(page: Page): Promise<void> {
  await expect(call(page, 'preflightAndQuery')).resolves.toEqual({
    preflightComplete: true,
    explicitMerkleVerified: true,
    entryCount: 0,
    totalBalanceSats: '0',
    isWhale: false,
  });
}

function loadFixture(): PaymentTwoProviderFixtureV1 {
  const encoded = process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_FIXTURE;
  if (!encoded) throw new Error('joined CLN global setup did not publish its fixture');
  const fixture = JSON.parse(encoded) as PaymentTwoProviderFixtureV1;
  if (!fixture.testOnly
      || !fixture.deterministic
      || fixture.fundsCapable
      || fixture.network !== 'regtest'
      || fixture.settlementMode !== 'external'
      || fixture.providers.length !== 2
      || fixture.providers[0].expectedPayeePubkeyHex
        !== fixture.providers[1].expectedPayeePubkeyHex) {
    throw new Error('joined CLN test refused a non-local or non-external fixture');
  }
  return fixture;
}

async function readyPage(
  context: BrowserContext,
  fixture: PaymentTwoProviderFixtureV1,
  providerFrames: Map<string, Buffer[]>,
): Promise<Page> {
  for (const provider of fixture.providers) {
    expect(provider.serverWsUrl).toBe(new URL(provider.serverWsUrl).toString());
    providerFrames.set(provider.serverWsUrl, []);
  }
  const page = await context.newPage();
  page.on('websocket', (socket) => {
    const frames = providerFrames.get(socket.url());
    if (!frames) return;
    socket.on('framesent', ({ payload }) => {
      frames.push(typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload);
    });
  });
  await page.goto('/e2e/payment-two-provider.html');
  await expect(page.locator('html')).toHaveAttribute('data-payment-two-provider-ready', 'true');
  return page;
}

function captureIssuerRequests(
  context: BrowserContext,
  fixture: PaymentTwoProviderFixtureV1,
  claimBodies: Buffer[],
): Map<string, string[]> {
  const paths = new Map(
    fixture.providers.map((provider) => [provider.issuerOrigin, [] as string[]]),
  );
  context.on('request', (request) => {
    const url = new URL(request.url());
    const observed = paths.get(url.origin);
    if (!observed) return;
    observed.push(url.pathname);
    if (url.pathname.endsWith('/claim')) {
      claimBodies.push(request.postDataBuffer() ?? Buffer.alloc(0));
    }
  });
  return paths;
}

async function assertProviderObservationsExclude(
  fixture: PaymentTwoProviderFixtureV1,
  providerFrames: Map<string, Buffer[]>,
  needles: Buffer[],
): Promise<void> {
  await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  for (const provider of fixture.providers) {
    const frames = providerFrames.get(new URL(provider.serverWsUrl).toString()) ?? [];
    expect(frames.length).toBeGreaterThan(0);
    const transcript = Buffer.concat(frames);
    const log = Buffer.from(await readFile(provider.serverLogPath));
    for (const needle of needles) {
      expect(transcript.includes(needle)).toBe(false);
      expect(transcript.includes(Buffer.from(needle.toString('hex'), 'ascii'))).toBe(false);
      expect(log.includes(needle)).toBe(false);
      expect(log.includes(Buffer.from(needle.toString('hex'), 'ascii'))).toBe(false);
    }
    expect(log.toString('utf8')).toContain('Service admission V1: enforced');
  }
}

function payClnRegtestInvoice(invoice: string): Buffer {
  const executable = process.env.BITCOINPIR_PAYMENT_CLN_CLI ?? '/opt/homebrew/bin/lightning-cli';
  const payerDirectory = requiredEnvironment('BITCOINPIR_PAYMENT_CLN_PAYER_DIR');
  const result = spawnSync(executable, [
    '--lightning-dir',
    payerDirectory,
    '--network=regtest',
    '--notifications=none',
    'xpay',
    invoice,
  ], {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`local CLN regtest payment failed (${result.status ?? 'spawn'})`, {
      cause: result.error,
    });
  }
  let response: unknown;
  try {
    response = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error('local CLN regtest payer returned non-JSON output', { cause: error });
  }
  if (!response || typeof response !== 'object') {
    throw new Error('local CLN regtest payer returned an invalid response');
  }
  const paid = response as Record<string, unknown>;
  const amountMsat = parseClnMillisatoshi(paid.amount_msat);
  const sentMsat = parseClnMillisatoshi(paid.amount_sent_msat);
  if (typeof paid.payment_preimage !== 'string'
      || !/^[0-9a-f]{64}$/.test(paid.payment_preimage)
      || paid.failed_parts !== 0
      || typeof paid.successful_parts !== 'number'
      || !Number.isSafeInteger(paid.successful_parts)
      || paid.successful_parts < 1
      || amountMsat < 1n
      || sentMsat < amountMsat) {
    throw new Error('local CLN regtest payer returned an incomplete success result');
  }
  return Buffer.from(paid.payment_preimage, 'hex');
}

function parseClnMillisatoshi(value: unknown): bigint {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === 'string' && /^\d+(?:msat)?$/.test(value)) {
    return BigInt(value.replace(/msat$/, ''));
  }
  if (value && typeof value === 'object') {
    const msat = (value as { msat?: unknown }).msat;
    if (typeof msat === 'number' && Number.isSafeInteger(msat) && msat >= 0) {
      return BigInt(msat);
    }
  }
  throw new Error('local CLN regtest payer returned a malformed millisatoshi amount');
}

function bolt11PaymentHash(invoice: string): Buffer {
  const separator = invoice.lastIndexOf('1');
  if (separator <= 0 || separator + 7 >= invoice.length) {
    throw new Error('BOLT11 invoice is not canonical bech32');
  }
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const words = Array.from(invoice.slice(separator + 1, -6), (character) => {
    const value = charset.indexOf(character);
    if (value < 0) throw new Error('BOLT11 invoice contains a non-bech32 character');
    return value;
  });
  let cursor = 7;
  while (cursor + 3 <= words.length - 104) {
    const tag = charset[words[cursor]];
    const length = words[cursor + 1] * 32 + words[cursor + 2];
    cursor += 3;
    if (cursor + length > words.length - 104) {
      throw new Error('BOLT11 tagged field exceeds the signed data region');
    }
    const field = words.slice(cursor, cursor + length);
    cursor += length;
    if (tag === 'p') {
      const decoded = convertBits(field, 5, 8);
      if (decoded.length !== 32) throw new Error('BOLT11 payment hash is not 32 bytes');
      return Buffer.from(decoded);
    }
  }
  throw new Error('BOLT11 invoice omitted its payment hash');
}

function convertBits(values: number[], fromBits: number, toBits: number): number[] {
  let accumulator = 0;
  let bits = 0;
  const out: number[] = [];
  const mask = (1 << toBits) - 1;
  for (const value of values) {
    if (value < 0 || value >= (1 << fromBits)) throw new Error('invalid bech32 word');
    accumulator = (accumulator << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((accumulator >> bits) & mask);
    }
  }
  if (bits >= fromBits || ((accumulator << (toBits - bits)) & mask) !== 0) {
    throw new Error('BOLT11 payment hash has non-zero padding');
  }
  return out;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for joined CLN E2E`);
  return value;
}

function call<K extends keyof HarnessApi>(
  page: Page,
  method: K,
  ...args: HarnessApi[K] extends (...values: infer P) => unknown ? P : never
): Promise<HarnessApi[K] extends (...values: never[]) => infer R ? Awaited<R> : never> {
  return page.evaluate(
    async ({ method: name, args: values }) => {
      const fn = window.paymentTwoProviderTest[name] as (...items: unknown[]) => unknown;
      return fn(...values);
    },
    { method, args },
  ) as Promise<HarnessApi[K] extends (...values: never[]) => infer R ? Awaited<R> : never>;
}
