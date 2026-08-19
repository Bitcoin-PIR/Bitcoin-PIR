import { describe, expect, it, vi } from 'vitest';

import {
  BatV2PublicClassCatalogResolverV2,
  MAX_BAT_V2_PUBLIC_CLASS_BYTES_V2,
  parseBatV2PublicClassCatalogV2,
  parseTrustedBatV2PublicClassCatalogRefV2,
  type BatV2PublicClassEntryV2,
} from '../bat-v2-class-catalog.js';
import { bytesToHex, hexToBytes, sha256 } from '../hash.js';
import { ProviderAdmissionSessionV1 } from '../service-admission.js';
import type { ServiceOfferViewV1, WasmVerifiedBatV2RedemptionV2 } from '../sdk-bridge.js';

const ISSUER = '11'.repeat(32);
const CLASS_ID = '22'.repeat(32);
const PROVIDER = '33'.repeat(32);
const POLICY = '44'.repeat(32);
const SCOPE = '55'.repeat(32);
const POLICY_KEY = '66'.repeat(32);
const BASE = 'https://web.example/app';

function digest(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

function member(overrides: Record<string, unknown> = {}) {
  return {
    providerIdHex: PROVIDER,
    policyDigestHex: POLICY,
    scopeIdHex: SCOPE,
    offerId: 7,
    ...overrides,
  };
}

function entry(
  epoch: number,
  status: 'current' | 'retained',
  classBytes: Uint8Array,
  overrides: Record<string, unknown> = {},
) {
  const artifactSha256Hex = digest(classBytes);
  return {
    issuerIdHex: ISSUER,
    classIdHex: CLASS_ID,
    classKeyEpoch: String(epoch),
    classDigestHex: `${epoch.toString(16).padStart(2, '0')}`.repeat(32),
    batKeyIdHex: `${(epoch + 16).toString(16).padStart(2, '0')}`.repeat(32),
    keyNotBeforeUnix: '1000',
    keyNotAfterUnix: '18446744073709551615',
    status,
    artifact: {
      path: `/proofs/bat-v2/classes/${artifactSha256Hex}.bin`,
      sha256Hex: artifactSha256Hex,
    },
    members: [member()],
    ...overrides,
  };
}

function catalog(entries: unknown[]) {
  return { version: 2, entries };
}

function offer(overrides: Partial<ServiceOfferViewV1> = {}): ServiceOfferViewV1 {
  return {
    offerId: 7,
    acquisition: 'bolt11',
    authorization: 'cashu-bat-v2',
    freeMode: 'not-free',
    verification: 'shared-issuer-online',
    deploymentStatus: 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex: ISSUER,
    keyIdHex: CLASS_ID,
    batVerificationKeyFingerprintHex: '77'.repeat(32),
    arcVerificationKeyFingerprintHex: '',
    endpoint: 'https://issuer.example',
    credentialCount: 2,
    credentialPresentationLimit: 1,
    privacyLeakageBits: 0,
    ...overrides,
  };
}

function setup(entries: ReturnType<typeof entry>[], artifacts: Uint8Array[]) {
  const serialized = JSON.stringify(catalog(entries));
  const catalogBytes = new TextEncoder().encode(serialized);
  const catalogSha = digest(catalogBytes);
  const catalogPath = `/proofs/bat-v2/catalogs/${catalogSha}.json`;
  const bodies = new Map<string, Uint8Array>([[catalogPath, catalogBytes]]);
  entries.forEach((value, index) => bodies.set(value.artifact.path, artifacts[index]));
  const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    expect(init).toMatchObject({ credentials: 'omit', redirect: 'error', cache: 'no-store' });
    const path = new URL(String(url)).pathname;
    const body = bodies.get(path);
    return body ? new Response(body.slice(), { status: 200 }) : new Response(null, { status: 404 });
  }) as unknown as typeof fetch;
  const resolver = new BatV2PublicClassCatalogResolverV2({
    version: 2,
    path: catalogPath,
    sha256Hex: catalogSha,
  }, { baseHref: BASE, fetchImpl, nowUnix: () => 1_500n });
  return { resolver, fetchImpl, bodies, serialized };
}

const selector = {
  role: 'first',
  providerIdHex: PROVIDER,
  policyDigestHex: POLICY,
  scopeIdHex: SCOPE,
  offerId: 7,
  offer: offer(),
};

describe('canonical BAT V2 public class catalog', () => {
  it('accepts one explicit current head and freezes exact canonical members', () => {
    const parsed = parseBatV2PublicClassCatalogV2(JSON.stringify(catalog([
      entry(1, 'current', new Uint8Array([1, 2, 3])),
    ])));
    expect(parsed.entries[0].status).toBe('current');
    expect(Object.isFrozen(parsed.entries[0].members)).toBe(true);
  });

  it('rejects V1, unknown fields, unsorted members, and partial refs', () => {
    const good = entry(1, 'current', new Uint8Array([1]));
    expect(() => parseBatV2PublicClassCatalogV2(JSON.stringify({ version: 1, entries: [good] })))
      .toThrow(/unknown version/);
    expect(() => parseBatV2PublicClassCatalogV2(JSON.stringify(catalog([
      { ...good, dynamicIssuerUrl: 'https://issuer.example/class' },
    ])))).toThrow(/unknown, missing, or non-canonical/);
    expect(() => parseBatV2PublicClassCatalogV2(JSON.stringify(catalog([{
      ...good,
      members: [member({ providerIdHex: '99'.repeat(32) }), member()],
    }])))).toThrow(/strictly canonical-sorted/);
    expect(() => parseTrustedBatV2PublicClassCatalogRefV2({
      version: 2,
      path: `/proofs/bat-v2/catalogs/${'aa'.repeat(32)}.json`,
    })).toThrow(/unknown, missing/);
  });

  it('requires exactly one explicit current head per issuer/class', () => {
    const first = entry(1, 'current', new Uint8Array([1]));
    const second = entry(2, 'current', new Uint8Array([2]));
    expect(() => parseBatV2PublicClassCatalogV2(JSON.stringify(catalog([first, second]))))
      .toThrow(/exactly one explicit current/);
    expect(() => parseBatV2PublicClassCatalogV2(JSON.stringify(catalog([
      { ...first, status: 'retained' },
      { ...second, status: 'retained' },
    ])))).toThrow(/exactly one explicit current/);
  });
});

describe('current exact class resolution', () => {
  it('selects the explicit current head during an overlapping retained rotation', async () => {
    const oldBytes = new Uint8Array([1, 1, 1]);
    const currentBytes = new Uint8Array([2, 2, 2]);
    const old = entry(1, 'retained', oldBytes);
    const current = entry(2, 'current', currentBytes);
    const { resolver, fetchImpl } = setup([old, current], [oldBytes, currentBytes]);
    const resolved = await resolver.resolveCurrent(selector);
    expect(Array.from(resolved.classBytes)).toEqual(Array.from(currentBytes));
    expect(resolved.binding.classKeyEpoch).toBe('2');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['V1 authorization', { offer: offer({ authorization: 'cashu-bat' }) }],
    ['cross class', { offer: offer({ keyIdHex: '88'.repeat(32) }) }],
    ['unknown member', { policyDigestHex: '99'.repeat(32) }],
  ])('fails closed for %s', async (_label, override) => {
    const bytes = new Uint8Array([3]);
    const { resolver } = setup([entry(1, 'current', bytes)], [bytes]);
    await expect(resolver.resolveCurrent({ ...selector, ...override })).rejects.toThrow();
  });

  it('rejects inactive heads, hash mismatches, and over-limit streams', async () => {
    const bytes = new Uint8Array([4]);
    const inactive = entry(1, 'current', bytes, { keyNotAfterUnix: '1499' });
    await expect(setup([inactive], [bytes]).resolver.resolveCurrent(selector))
      .rejects.toThrow(/inactive/);

    const mismatch = setup([entry(1, 'current', bytes)], [bytes]);
    mismatch.bodies.set((JSON.parse(mismatch.serialized).entries[0] as BatV2PublicClassEntryV2)
      .artifact.path, new Uint8Array([5]));
    await expect(mismatch.resolver.resolveCurrent(selector)).rejects.toThrow(/SHA-256 mismatch/);

    const oversized = new Uint8Array(MAX_BAT_V2_PUBLIC_CLASS_BYTES_V2 + 1);
    const limited = setup([entry(1, 'current', bytes)], [oversized]);
    await expect(limited.resolver.resolveCurrent(selector)).rejects.toThrow(/byte fetch limit/);
  });
});

describe('retained exact class resolution', () => {
  it('maps wallet binding plus provider to one member, retained policy, and opaque handle', async () => {
    const classBytes = new Uint8Array([9, 8, 7]);
    const retainedEntry = entry(1, 'retained', classBytes);
    const currentBytes = new Uint8Array([6, 5, 4]);
    const currentEntry = entry(2, 'current', currentBytes);
    const { resolver } = setup(
      [retainedEntry, currentEntry],
      [classBytes, currentBytes],
    );
    const verified: WasmVerifiedBatV2RedemptionV2 = {
      free: vi.fn(),
      providerIdHex: PROVIDER,
      policyDigestHex: POLICY,
      scopeIdHex: SCOPE,
      offerId: 7,
      classIdHex: CLASS_ID,
      classBindingJson: () => ({
        issuerIdHex: retainedEntry.issuerIdHex,
        classIdHex: retainedEntry.classIdHex,
        classDigestHex: retainedEntry.classDigestHex,
        classKeyEpoch: retainedEntry.classKeyEpoch,
        batKeyIdHex: retainedEntry.batKeyIdHex,
      }),
      assertRedemptionReady: vi.fn(),
    };
    const accepted = {
      free: vi.fn(),
      providerIdHex: PROVIDER,
      policyDigestHex: POLICY,
      scopeIdHex: SCOPE,
      offerId: 7,
      verifyBatV2Redemption: vi.fn(() => verified),
    };
    const ready = vi.fn();
    const port = {
      assertTrustAnchor: vi.fn(),
      captureReadinessGuard: vi.fn(() => ready),
      fetchRetainedBatV2Policy: vi.fn(async (..._args: unknown[]) => accepted),
    };
    const session = new ProviderAdmissionSessionV1(
      {} as never,
      port as never,
      { providerId: hexToBytes(PROVIDER), policySigningKey: hexToBytes(POLICY_KEY) },
      {
        backend: 'dpf-pir',
        workload: 'dpf-query',
        protocolVersion: 1,
        expectedDatasetManifestRootHex: '77'.repeat(32),
      },
    );
    const resolved = await resolver.resolveRetained({
      binding: {
        issuerIdHex: retainedEntry.issuerIdHex,
        classIdHex: retainedEntry.classIdHex,
        classDigestHex: retainedEntry.classDigestHex,
        classKeyEpoch: retainedEntry.classKeyEpoch,
        batKeyIdHex: retainedEntry.batKeyIdHex,
      },
      providerIdHex: PROVIDER,
      session,
    });
    expect(resolved.verifiedRedemption).toBe(verified);
    expect(port.fetchRetainedBatV2Policy).toHaveBeenCalledOnce();
    const args = port.fetchRetainedBatV2Policy.mock.calls[0];
    expect(bytesToHex(args[2] as Uint8Array)).toBe(POLICY);
    expect(bytesToHex(args[3] as Uint8Array)).toBe(SCOPE);
    expect(args[4]).toBe(7);
    expect(accepted.verifyBatV2Redemption).toHaveBeenCalledOnce();
    expect(ready).toHaveBeenCalledTimes(3);
    resolved.classArtifact.classBytes.fill(0);
    resolved.verifiedRedemption.free();
    session.close();
  });

  it.each([
    ['digest', { classDigestHex: 'ab'.repeat(32) }],
    ['epoch', { classKeyEpoch: '9' }],
    ['BAT key', { batKeyIdHex: 'ac'.repeat(32) }],
  ])('rejects a retained handle with a mismatched verified %s before AUTH', async (
    _label,
    mismatch,
  ) => {
    const classBytes = new Uint8Array([9, 8, 7]);
    const retainedEntry = entry(1, 'retained', classBytes);
    const binding = {
      issuerIdHex: retainedEntry.issuerIdHex,
      classIdHex: retainedEntry.classIdHex,
      classDigestHex: retainedEntry.classDigestHex,
      classKeyEpoch: retainedEntry.classKeyEpoch,
      batKeyIdHex: retainedEntry.batKeyIdHex,
    };
    const verified: WasmVerifiedBatV2RedemptionV2 = {
      free: vi.fn(),
      providerIdHex: PROVIDER,
      policyDigestHex: POLICY,
      scopeIdHex: SCOPE,
      offerId: 7,
      classIdHex: CLASS_ID,
      classBindingJson: () => ({ ...binding, ...mismatch }),
      assertRedemptionReady: vi.fn(),
    };
    const accepted = {
      free: vi.fn(),
      providerIdHex: PROVIDER,
      policyDigestHex: POLICY,
      scopeIdHex: SCOPE,
      offerId: 7,
      verifyBatV2Redemption: vi.fn(() => verified),
    };
    const authorizeBatV2 = vi.fn();
    const port = {
      assertTrustAnchor: vi.fn(),
      captureReadinessGuard: vi.fn(() => vi.fn()),
      fetchRetainedBatV2Policy: vi.fn(async (..._args: unknown[]) => accepted),
      authorizeBatV2,
    };
    const session = new ProviderAdmissionSessionV1(
      {} as never,
      port as never,
      { providerId: hexToBytes(PROVIDER), policySigningKey: hexToBytes(POLICY_KEY) },
      {
        backend: 'dpf-pir',
        workload: 'dpf-query',
        protocolVersion: 1,
        expectedDatasetManifestRootHex: '77'.repeat(32),
      },
    );
    await expect(session.verifyRetainedBatV2ClassMember(
      member(),
      { classBytes, binding },
    )).rejects.toThrow(/exact signed class binding/);
    expect(authorizeBatV2).not.toHaveBeenCalled();
    expect(verified.free).toHaveBeenCalledOnce();
    expect(accepted.free).toHaveBeenCalledOnce();
    session.close();
  });

  it('rejects a provider with multiple members before retained policy fetch', async () => {
    const bytes = new Uint8Array([1, 9]);
    const duplicatedProvider = entry(1, 'current', bytes, {
      members: [member(), member({ offerId: 8 })],
    });
    const { resolver } = setup([duplicatedProvider], [bytes]);
    const session = { verifyRetainedBatV2ClassMember: vi.fn() } as unknown as ProviderAdmissionSessionV1;
    await expect(resolver.resolveRetained({
      binding: {
        issuerIdHex: duplicatedProvider.issuerIdHex,
        classIdHex: duplicatedProvider.classIdHex,
        classDigestHex: duplicatedProvider.classDigestHex,
        classKeyEpoch: duplicatedProvider.classKeyEpoch,
        batKeyIdHex: duplicatedProvider.batKeyIdHex,
      },
      providerIdHex: PROVIDER,
      session,
    })).rejects.toThrow(/no unique exact class member/);
    expect(session.verifyRetainedBatV2ClassMember).not.toHaveBeenCalled();
  });
});
