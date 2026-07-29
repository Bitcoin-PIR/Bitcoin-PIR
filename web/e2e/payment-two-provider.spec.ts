import { readFile } from 'node:fs/promises';

import { expect, type BrowserContext, type Page, test } from '@playwright/test';

import type {
  PaymentTwoProviderFixtureV1,
  PaymentTwoProviderVariantV1,
} from './payment-two-provider.global-setup.js';

interface HarnessApi {
  initialize(fixture: PaymentTwoProviderFixtureV1): Promise<{
    secureChannel: true;
    attestationBoundary: [string, string];
    databaseProofInstalled: true;
    databaseProofBoundary: string;
    providers: Array<{
      providerIdHex: string;
      policyDigestHex: string;
      scopeIdHex: string;
      methods: string[];
      arcKeyIdHex: string | null;
      issuerOrigin: string;
      payeePubkeyHex: string;
    }>;
  }>;
  selectVariant(variant: PaymentTwoProviderVariantV1): Array<{
    index: 0 | 1;
    offerCount: number;
    hasFree: boolean;
    authorization: string;
    acquisition: string;
    freeMode: string;
    deploymentStatus: string;
  }>;
  acquireLeg(index: 0 | 1): Promise<{
    invoice: string | null;
    count: number;
    binding: {
      providerIdHex: string;
      policyDigestHex: string;
      scopeIdHex: string;
      offerId: number;
      scheme: string;
    } | null;
  }>;
  authorizeLeg(index: 0 | 1, corruptBeforeSend?: boolean): Promise<{
    scopeIdHex: string;
    enforcedProfile: number;
  }>;
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
  verifiedOfferInventory(): Array<{
    index: 0 | 1;
    offerCount: number;
    hasFree: boolean;
    authorization: string;
    acquisition: string;
    freeMode: string;
    deploymentStatus: string;
  }>;
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

test('browser buys independent direct/BAT capabilities and both real provider gates consume once',
  async ({ context }) => {
    const fixture = loadFixture();
    const providerFrames = new Map<string, Buffer[]>();
    const claimBodies: Buffer[] = [];
    captureIssuerClaims(context, fixture, claimBodies);
    const page = await readyPage(context, fixture, providerFrames);

    const initialized = await call(page, 'initialize', fixture);
    expect(initialized.secureChannel).toBe(true);
    expect(initialized.attestationBoundary).toEqual(['noSevHost', 'noSevHost']);
    expect(initialized.databaseProofInstalled).toBe(true);
    expect(initialized.databaseProofBoundary).toContain('not AMD SEV-SNP signature');
    expect(initialized.providers).toHaveLength(2);
    expect(initialized.providers[0].providerIdHex).not.toBe(
      initialized.providers[1].providerIdHex,
    );
    expect(initialized.providers[0].policyDigestHex).not.toBe(
      initialized.providers[1].policyDigestHex,
    );
    expect(initialized.providers[0].methods).toEqual(['free', 'bolt11-direct-receipt']);
    expect(initialized.providers[1].methods).toEqual(['cashu-bat', 'arc-experimental']);
    expect(initialized.providers[0].arcKeyIdHex).toBeNull();
    expect(initialized.providers[1].arcKeyIdHex).toMatch(/^[0-9a-f]{64}$/);
    expect(initialized.providers[0].issuerOrigin).not.toBe(
      initialized.providers[1].issuerOrigin,
    );
    expect(initialized.providers[0].payeePubkeyHex).not.toBe(
      initialized.providers[1].payeePubkeyHex,
    );
    for (const provider of fixture.providers) {
      expect(provider.issuerIdHex).not.toBe(provider.providerIdHex);
      expect(provider.issuerIdHex).not.toBe(provider.policySigningPubkeyHex);
      expect(provider.providerIdHex).not.toBe(provider.policySigningPubkeyHex);
      if (provider.arcKeyIdHex) {
        expect(provider.arcKeyIdHex).not.toBe(provider.issuerIdHex);
        expect(provider.arcKeyIdHex).not.toBe(provider.policySigningPubkeyHex);
      }
    }
    expect(await call(page, 'selectVariant', 'direct-bat')).toEqual([
      {
        index: 0,
        offerCount: 2,
        hasFree: true,
        authorization: 'bolt11-direct-receipt',
        acquisition: 'bolt11',
        freeMode: 'not-free',
        deploymentStatus: 'stable',
      },
      {
        index: 1,
        offerCount: 2,
        hasFree: false,
        authorization: 'cashu-bat',
        acquisition: 'bolt11',
        freeMode: 'not-free',
        deploymentStatus: 'stable',
      },
    ]);

    const first = await call(page, 'acquireLeg', 0);
    const second = await call(page, 'acquireLeg', 1);
    expect(first.invoice).toMatch(/^lnbcrt[0-9]+[munp]?1/);
    expect(second.invoice).toMatch(/^lnbcrt[0-9]+[munp]?1/);
    if (!first.invoice || !second.invoice || !first.binding || !second.binding) {
      throw new Error('paid browser variant did not return invoice-bound capabilities');
    }
    expect(first.invoice).not.toBe(second.invoice);
    expect(first.binding.providerIdHex).not.toBe(second.binding.providerIdHex);
    expect(first.binding.scheme).toBe('bolt11-direct-receipt');
    expect(second.binding.scheme).toBe('cashu-bat');
    expect(claimBodies).toHaveLength(2);
    await expect(call(page, 'capabilityCount', 0)).resolves.toBe(1);
    await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);

    const firstHash = bolt11PaymentHash(first.invoice);
    const secondHash = bolt11PaymentHash(second.invoice);
    expect(firstHash.equals(secondHash)).toBe(false);

    await expect(call(page, 'authorizeLeg', 0)).resolves.toEqual({
      scopeIdHex: fixture.providers[0].scopeIdHex,
      enforcedProfile: fixture.providers[0].entitlementProfile,
    });
    await expect(call(page, 'authorizeLeg', 1)).resolves.toEqual({
      scopeIdHex: fixture.providers[1].scopeIdHex,
      enforcedProfile: fixture.providers[1].entitlementProfile,
    });
    await expect(call(page, 'capabilityCount', 0)).resolves.toBe(0);
    await expect(call(page, 'capabilityCount', 1)).resolves.toBe(0);

    await expect(call(page, 'preflightAndQuery')).resolves.toEqual({
      preflightComplete: true,
      explicitMerkleVerified: true,
      entryCount: 0,
      totalBalanceSats: '0',
      isWhale: false,
    });

    // The actual 20-byte scripthash submitted to queryBatchVerified is a leakage
    // needle. Both outgoing provider frames must be encrypted, and neither
    // provider's ordinary log may retain it, an invoice, or a payment hash.
    const queryScriptHash = Buffer.alloc(20, 0x42);
    const needles = [
      Buffer.from(first.invoice, 'utf8'),
      Buffer.from(second.invoice, 'utf8'),
      firstHash,
      secondHash,
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

    await expect(call(page, 'replaySpentCapability', 0)).resolves.toMatch(/invalid-or-spent/i);
    await expect(call(page, 'replaySpentCapability', 1)).resolves.toMatch(/invalid-or-spent/i);

    await assertProviderObservationsExcludeInvoiceHashAndQuerySentinel(
      fixture,
      providerFrames,
      needles,
    );
    for (const claim of claimBodies) {
      for (const invoice of [first.invoice, second.invoice]) {
        expect(claim.includes(Buffer.from(invoice, 'utf8'))).toBe(false);
      }
      expect(claim.includes(firstHash)).toBe(false);
      expect(claim.includes(secondHash)).toBe(false);
      expect(claim.includes(queryScriptHash)).toBe(false);
    }
    expect(await call(page, 'localStorageSnapshot')).toEqual({});
    expect(await page.evaluate(
      () => window.__paymentTwoProviderLocalStorageWrites ?? [],
    )).toEqual([]);
  });

test('one provider rejection preserves the other grant and cannot downgrade to free',
  async ({ context }) => {
    const fixture = loadFixture();
    const providerFrames = new Map<string, Buffer[]>();
    const page = await readyPage(context, fixture, providerFrames);
    await call(page, 'initialize', fixture);
    const offers = await call(page, 'selectVariant', 'direct-bat');
    expect(offers).toEqual([
      {
        index: 0,
        offerCount: 2,
        hasFree: true,
        authorization: 'bolt11-direct-receipt',
        acquisition: 'bolt11',
        freeMode: 'not-free',
        deploymentStatus: 'stable',
      },
      {
        index: 1,
        offerCount: 2,
        hasFree: false,
        authorization: 'cashu-bat',
        acquisition: 'bolt11',
        freeMode: 'not-free',
        deploymentStatus: 'stable',
      },
    ]);
    await call(page, 'acquireLeg', 0);
    await call(page, 'acquireLeg', 1);

    await expect(call(page, 'authorizeLeg', 0)).resolves.toEqual({
      scopeIdHex: fixture.providers[0].scopeIdHex,
      enforcedProfile: fixture.providers[0].entitlementProfile,
    });
    await expect(call(page, 'authorizeLeg', 1, true)).rejects.toThrow(
      /AmbiguousCapabilitySpendErrorV1|no fallback or retry is permitted/i,
    );
    await expect(call(page, 'capabilityCount', 0)).resolves.toBe(0);
    await expect(call(page, 'capabilityCount', 1)).resolves.toBe(0);

    // Provider 0's durable grant remains spent even though provider 1's
    // independent leg rejected. There is no pair transaction to roll back.
    // This browser scenario proves local vault retirement and provider-0
    // replay rejection; it does not claim a full provider-1 spent-set audit.
    await expect(call(page, 'replaySpentCapability', 0)).resolves.toMatch(/invalid-or-spent/i);
    expect(await call(page, 'verifiedOfferInventory')).toEqual(offers);
    expect(await call(page, 'localStorageSnapshot')).toEqual({});
  });

test('signed durable Free/IP and experimental ARC reach real stores before one verified DPF query',
  async ({ context }) => {
    const fixture = loadFixture();
    const providerFrames = new Map<string, Buffer[]>();
    const claimBodies: Buffer[] = [];
    const issuerPaths = captureIssuerRequests(context, fixture);
    captureIssuerClaims(context, fixture, claimBodies);
    const page = await readyPage(context, fixture, providerFrames);

    await call(page, 'initialize', fixture);
    expect(await call(page, 'selectVariant', 'free-arc-experimental')).toEqual([
      {
        index: 0,
        offerCount: 2,
        hasFree: true,
        authorization: 'free',
        acquisition: 'free',
        freeMode: 'ip-rate-limited',
        deploymentStatus: 'stable',
      },
      {
        index: 1,
        offerCount: 2,
        hasFree: false,
        authorization: 'arc-experimental',
        acquisition: 'bolt11',
        freeMode: 'not-free',
        deploymentStatus: 'experimental',
      },
    ]);

    // Calling the common acquisition entry point for the exact signed Free
    // offer must not contact either fake Lightning issuer or create an invoice.
    await expect(call(page, 'acquireLeg', 0)).resolves.toEqual({
      invoice: null,
      count: 0,
      binding: null,
    });
    expect(issuerPaths.get(fixture.providers[0].issuerOrigin)).toEqual([]);
    expect(issuerPaths.get(fixture.providers[1].issuerOrigin)).toEqual([]);

    const arc = await call(page, 'acquireLeg', 1);
    expect(arc.invoice).toMatch(/^lnbcrt[0-9]+[munp]?1/);
    expect(arc.count).toBe(1);
    expect(arc.binding?.scheme).toBe('arc-experimental');
    if (!arc.invoice || !arc.binding) {
      throw new Error('experimental ARC acquisition did not return its exact capability binding');
    }
    expect(issuerPaths.get(fixture.providers[0].issuerOrigin)).toEqual([]);
    const arcIssuerPaths = issuerPaths.get(fixture.providers[1].issuerOrigin) ?? [];
    expect(arcIssuerPaths).toEqual(expect.arrayContaining([
      '/v1/quote-keys/current',
      '/v1/quotes/bolt11',
    ]));
    expect(arcIssuerPaths.some((path) =>
      /^\/v1\/quotes\/[0-9a-f]{64}\/claim$/.test(path))).toBe(true);
    expect(claimBodies).toHaveLength(1);
    await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);

    await expect(call(page, 'authorizeLeg', 0)).resolves.toEqual({
      scopeIdHex: fixture.providers[0].scopeIdHex,
      enforcedProfile: fixture.providers[0].entitlementProfile,
    });
    await expect(call(page, 'authorizeLeg', 1)).resolves.toEqual({
      scopeIdHex: fixture.providers[1].scopeIdHex,
      enforcedProfile: fixture.providers[1].entitlementProfile,
    });
    // ARC has four presentations. The encrypted successor nonce state remains
    // in IndexedDB only after the vault's persist-before-release transition.
    await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);

    await expect(call(page, 'preflightAndQuery')).resolves.toEqual({
      preflightComplete: true,
      explicitMerkleVerified: true,
      entryCount: 0,
      totalBalanceSats: '0',
      isWhale: false,
    });

    // The signed one-slot/one-hour Free/IP bucket is provider-local and
    // durable across a new secure connection. Provider 0's rejection must not
    // affect provider 1's independent ARC key, store, or presentation budget.
    await expect(call(page, 'replayFreeQuota', 0)).resolves.toMatch(/server-busy/i);
    await expect(call(page, 'authorizeLeg', 1)).resolves.toEqual({
      scopeIdHex: fixture.providers[1].scopeIdHex,
      enforcedProfile: fixture.providers[1].entitlementProfile,
    });
    await expect(call(page, 'capabilityCount', 1)).resolves.toBe(1);
    await expect(call(page, 'replaySpentCapability', 1)).resolves.toMatch(/invalid-or-spent/i);
    expect(issuerPaths.get(fixture.providers[0].issuerOrigin)).toEqual([]);
    expect(claimBodies).toHaveLength(1);

    const invoiceHash = bolt11PaymentHash(arc.invoice);
    const queryScriptHash = Buffer.alloc(20, 0x42);
    const needles = [Buffer.from(arc.invoice, 'utf8'), invoiceHash, queryScriptHash];
    for (const needle of needles) {
      await expect(call(
        page,
        'retainedReplayProofContains',
        1,
        Array.from(needle),
      )).resolves.toBe(false);
    }
    await assertProviderObservationsExcludeInvoiceHashAndQuerySentinel(
      fixture,
      providerFrames,
      needles,
    );
    for (const claim of claimBodies) {
      expect(claim.includes(Buffer.from(arc.invoice, 'utf8'))).toBe(false);
      expect(claim.includes(invoiceHash)).toBe(false);
      expect(claim.includes(queryScriptHash)).toBe(false);
    }
    expect(await call(page, 'localStorageSnapshot')).toEqual({});
    expect(await page.evaluate(
      () => window.__paymentTwoProviderLocalStorageWrites ?? [],
    )).toEqual([]);
  });

function loadFixture(): PaymentTwoProviderFixtureV1 {
  const encoded = process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_FIXTURE;
  if (!encoded) throw new Error('two-provider global setup did not publish its fixture');
  const fixture = JSON.parse(encoded) as PaymentTwoProviderFixtureV1;
  if (!fixture.testOnly
      || !fixture.deterministic
      || fixture.fundsCapable
      || fixture.network !== 'regtest'
      || !fixture.databaseProof
      || fixture.providers.length !== 2) {
    throw new Error('test refused a non-test or funds-capable fixture');
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

function captureIssuerClaims(
  context: BrowserContext,
  fixture: PaymentTwoProviderFixtureV1,
  claimBodies: Buffer[],
): void {
  const issuers = new Set(fixture.providers.map((provider) => provider.issuerOrigin));
  context.on('request', (request) => {
    const url = new URL(request.url());
    if (issuers.has(url.origin) && url.pathname.endsWith('/claim')) {
      claimBodies.push(request.postDataBuffer() ?? Buffer.alloc(0));
    }
  });
}

function captureIssuerRequests(
  context: BrowserContext,
  fixture: PaymentTwoProviderFixtureV1,
): Map<string, string[]> {
  const paths = new Map(
    fixture.providers.map((provider) => [provider.issuerOrigin, [] as string[]]),
  );
  context.on('request', (request) => {
    const url = new URL(request.url());
    const observed = paths.get(url.origin);
    if (observed) observed.push(url.pathname);
  });
  return paths;
}

async function assertProviderObservationsExcludeInvoiceHashAndQuerySentinel(
  fixture: PaymentTwoProviderFixtureV1,
  providerFrames: Map<string, Buffer[]>,
  needles: Buffer[],
): Promise<void> {
  await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  for (const provider of fixture.providers) {
    const frames = providerFrames.get(new URL(provider.serverWsUrl).toString()) ?? [];
    expect(frames.length).toBeGreaterThan(0);
    // Outgoing WebSocket frames are encrypted after upgrade, so the raw-frame
    // check primarily proves no plaintext regression. The provider log check
    // is separate. A direct receipt remains issuer-linkable by design; this
    // assertion covers only BOLT11 invoices, payment hashes, and the query
    // sentinel named by `needles`.
    const transcript = Buffer.concat(frames);
    const log = Buffer.from(await readFile(provider.serverLogPath));
    for (const needle of needles) {
      expect(transcript.includes(needle)).toBe(false);
      expect(transcript.includes(Buffer.from(needle.toString('hex'), 'ascii'))).toBe(false);
      expect(log.includes(needle)).toBe(false);
      expect(log.includes(Buffer.from(needle.toString('hex'), 'ascii'))).toBe(false);
    }
    const logText = log.toString('utf8');
    expect(logText).toContain('Service admission V1: enforced');
    expect(logText).not.toContain('UNSAFE DEBUG QUERY LOGGING ENABLED');
  }
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
