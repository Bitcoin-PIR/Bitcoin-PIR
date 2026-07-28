import { webcrypto } from 'node:crypto';
import { indexedDB as fakeIndexedDB } from 'fake-indexeddb';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  AdmissionCredentialVaultV1,
  validateBindingV1,
  validateCapabilityV1,
} from '../admission-vault.js';

const provider = '11'.repeat(32);
const policyDigest = '33'.repeat(32);
const scope = '22'.repeat(32);
const databaseName = 'bitcoinpir-admission-v1';
let opened: AdmissionCredentialVaultV1[] = [];
let observeLockRequest: ((name: string) => void) | undefined;

beforeEach(async () => {
  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    value: fakeIndexedDB,
  });
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  });
  const tails = new Map<string, Promise<unknown>>();
  observeLockRequest = undefined;
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: {
      locks: {
        request: <T>(name: string, _options: unknown, callback: () => Promise<T>) => {
          observeLockRequest?.(name);
          const previous = tails.get(name) ?? Promise.resolve();
          const result = previous.then(callback, callback);
          tails.set(name, result.then(() => undefined, () => undefined));
          return result;
        },
      },
    },
  });
  await deleteDatabase();
  opened = [];
});

afterEach(async () => {
  observeLockRequest = undefined;
  for (const vault of opened) vault.close();
  opened = [];
  await deleteDatabase();
});

describe('provider-scoped admission vault validation', () => {
  it('accepts all V1 paid capability families with exact provider binding', () => {
    for (const scheme of [
      'bolt11-direct-receipt',
      'cashu-ecash',
      'cashu-bat',
      'arc-experimental',
    ] as const) {
      expect(() => validateCapabilityV1({
        providerIdHex: provider.toUpperCase(),
        policyDigestHex: policyDigest,
        scopeIdHex: scope,
        offerId: 7,
        scheme,
        payload: new Uint8Array([1]),
      })).not.toThrow();
    }
  });

  it('rejects zero/cross-shape IDs, empty or oversized payloads, and unknown methods', () => {
    expect(() => validateBindingV1({
      providerIdHex: '00'.repeat(32),
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-bat',
    })).toThrow(/non-zero/);
    expect(() => validateCapabilityV1({
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-bat',
      payload: new Uint8Array(),
    })).toThrow(/canonical V1 proof bound/);
    expect(() => validateCapabilityV1({
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-bat',
      payload: new Uint8Array(12 * 1024 + 1),
    })).toThrow(/canonical V1 proof bound/);
    expect(() => validateBindingV1({
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'invoice' as never,
    })).toThrow(/unknown/);
  });

  it('does not select a capability after a policy rotates with reused scope and offer IDs', async () => {
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    await vault.putCapability({
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-ecash',
      payload: new Uint8Array([7]),
    });
    await expect(vault.takeSingleUseCapability({
      providerIdHex: provider,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-ecash',
    })).resolves.toBeNull();
    await expect(vault.takeSingleUseCapability({
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-ecash',
    })).resolves.toMatchObject({ payload: new Uint8Array([7]) });
  });

  it('zeroizes validation and ARC transition scratch buffers', async () => {
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    const binding = {
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-bat' as const,
    };
    await vault.putCapability({ ...binding, payload: new Uint8Array([7, 8, 9]) });
    let validationCopy: Uint8Array | undefined;
    await expect(vault.takeSingleUseCapability(binding, (candidate) => {
      validationCopy = candidate;
      throw new Error('reject fixture');
    })).rejects.toThrow(/reject fixture/);
    expect(validationCopy).toEqual(new Uint8Array(3));
    const retired = await vault.takeSingleUseCapability(binding);
    expect(retired?.payload).toEqual(new Uint8Array([7, 8, 9]));
    retired?.payload.fill(0);

    const arcBinding = { ...binding, offerId: 8, scheme: 'arc-experimental' as const };
    await vault.putCapability({ ...arcBinding, payload: new Uint8Array([1, 2, 3]) });
    let serializedState: Uint8Array | undefined;
    const successor = new Uint8Array([4, 5, 6]);
    const presentation = new Uint8Array([7, 8, 9]);
    const released = await vault.advanceArcCredential(arcBinding, (state) => {
      serializedState = state;
      return {
        nextState: successor,
        remaining: 1,
        releaseAfterPersisted: () => presentation,
        discard: () => undefined,
      };
    });
    expect(serializedState).toEqual(new Uint8Array(3));
    expect(successor).toEqual(new Uint8Array(3));
    expect(presentation).toEqual(new Uint8Array(3));
    expect(released).toEqual(new Uint8Array([7, 8, 9]));
    released?.fill(0);

    const invalidSuccessor = new Uint8Array([9, 9, 9]);
    let discardedInvalidTransition = false;
    await expect(vault.advanceArcCredential(arcBinding, () => ({
      nextState: invalidSuccessor,
      remaining: -1,
      releaseAfterPersisted: () => new Uint8Array([1]),
      discard: () => { discardedInvalidTransition = true; },
    }))).rejects.toThrow(/invalid state transition/);
    expect(discardedInvalidTransition).toBe(true);
    expect(invalidSuccessor).toEqual(new Uint8Array(3));
  });

  it('lists only aggregate non-secret retained bindings scoped by provider', async () => {
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    for (const payload of [new Uint8Array([1]), new Uint8Array([2])]) {
      await vault.putCapability({
        providerIdHex: provider,
        policyDigestHex: policyDigest,
        scopeIdHex: scope,
        offerId: 7,
        scheme: 'cashu-bat',
        payload,
      });
    }
    await vault.putCapability({
      providerIdHex: '44'.repeat(32),
      policyDigestHex: '55'.repeat(32),
      scopeIdHex: '66'.repeat(32),
      offerId: 8,
      scheme: 'bolt11-direct-receipt',
      payload: new Uint8Array([3]),
    });

    const inventory = await vault.listCapabilityInventory(provider);
    expect(inventory).toEqual([{
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-bat',
      count: 2,
    }]);
    expect(inventory[0]).not.toHaveProperty('payload');
    expect(inventory[0]).not.toHaveProperty('id');
  });

  it('deletes V2 capabilities and invoice recovery that lack a policy digest', async () => {
    await createLegacyV2Database();
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    await expect(vault.takeSingleUseCapability({
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      scheme: 'cashu-ecash',
    })).resolves.toBeNull();
    await expect(vault.listBolt11Recoveries()).resolves.toEqual([]);
  });

  it('atomically advances one provider policy checkpoint across tabs', async () => {
    const firstVault = await AdmissionCredentialVaultV1.open();
    const secondVault = await AdmissionCredentialVaultV1.open();
    opened.push(firstVault, secondVault);
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let markFirstEntered!: () => void;
    const firstEntered = new Promise<void>((resolve) => { markFirstEntered = resolve; });
    const seen: number[][] = [];

    const first = firstVault.advancePolicyCheckpoint(
      provider,
      new Uint8Array([1]),
      async (current) => {
        seen.push(Array.from(current));
        markFirstEntered();
        await firstGate;
        return { nextCheckpoint: new Uint8Array([2]), value: 'first' };
      },
    );
    // The vault hashes the provider ID before requesting the Web Lock, so two
    // same-tick callers have no specified queue order. Establish that the
    // first callback owns the lock before launching the contending tab.
    await firstEntered;
    let markSecondLockRequested!: () => void;
    const secondLockRequested = new Promise<void>((resolve) => {
      markSecondLockRequested = resolve;
    });
    observeLockRequest = (name) => {
      if (name.startsWith('bitcoinpir:policy:')) markSecondLockRequested();
    };
    const second = secondVault.advancePolicyCheckpoint(
      provider,
      new Uint8Array([1]),
      async (current) => {
        seen.push(Array.from(current));
        return { nextCheckpoint: new Uint8Array([3]), value: 'second' };
      },
    );
    await secondLockRequested;
    expect(seen).toEqual([[1]]);
    releaseFirst();
    await expect(Promise.all([first, second])).resolves.toEqual(['first', 'second']);
    expect(seen).toEqual([[1], [2]]);
    await expect(firstVault.getPolicyCheckpoint(provider)).resolves.toEqual(new Uint8Array([3]));
  });

  it('keeps the exact claim state while a stale tab waits, then resumes it after response loss', async () => {
    const firstVault = await AdmissionCredentialVaultV1.open();
    const secondVault = await AdmissionCredentialVaultV1.open();
    opened.push(firstVault, secondVault);
    const created = await firstVault.createBolt11Recovery({
      issuerEndpoint: 'https://issuer.example',
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      expectedScheme: 'bolt11-direct-receipt',
      state: new Uint8Array([1]),
    });
    let releaseLostResponse!: () => void;
    const lostResponse = new Promise<void>((resolve) => { releaseLostResponse = resolve; });
    let secondEntered = false;

    const first = firstVault.withBolt11Recovery(created.id, async (_recovery, locked) => {
      await locked.persistState(new Uint8Array([9, 9]));
      await lostResponse;
      throw new Error('claim HTTP response lost');
    });
    const second = secondVault.withBolt11Recovery(created.id, async (recovery, locked) => {
      secondEntered = true;
      expect(recovery.state).toEqual(new Uint8Array([9, 9]));
      await locked.complete([{
        providerIdHex: provider,
        policyDigestHex: policyDigest,
        scopeIdHex: scope,
        offerId: 7,
        scheme: 'bolt11-direct-receipt',
        payload: new Uint8Array([4]),
      }]);
      return 'recovered';
    });
    await Promise.resolve();
    expect(secondEntered).toBe(false);
    releaseLostResponse();
    await expect(first).rejects.toThrow(/response lost/);
    await expect(second).resolves.toBe('recovered');
    await expect(firstVault.getBolt11Recovery(created.id)).resolves.toBeNull();
  });

  it('refuses to install issuance under a different policy digest than its recovery', async () => {
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    const created = await vault.createBolt11Recovery({
      issuerEndpoint: 'https://issuer.example',
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 7,
      expectedScheme: 'bolt11-direct-receipt',
      state: new Uint8Array([1]),
    });
    await expect(vault.withBolt11Recovery(created.id, async (_recovery, locked) =>
      locked.complete([{
        providerIdHex: provider,
        policyDigestHex: '44'.repeat(32),
        scopeIdHex: scope,
        offerId: 7,
        scheme: 'cashu-bat',
        payload: new Uint8Array([4]),
      }]))).rejects.toThrow(/exact recovery policy binding/);
    await expect(vault.getBolt11Recovery(created.id)).resolves.toMatchObject({
      policyDigestHex: policyDigest,
    });
  });

  it('binds recovery completion to the exact signed capability family', async () => {
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    const created = await vault.createBolt11Recovery({
      issuerEndpoint: 'https://issuer.example',
      providerIdHex: provider,
      policyDigestHex: policyDigest,
      scopeIdHex: scope,
      offerId: 8,
      expectedScheme: 'cashu-bat',
      state: new Uint8Array([1]),
    });
    await expect(vault.withBolt11Recovery(created.id, async (_recovery, locked) =>
      locked.complete([{
        providerIdHex: provider,
        policyDigestHex: policyDigest,
        scopeIdHex: scope,
        offerId: 8,
        scheme: 'bolt11-direct-receipt',
        payload: new Uint8Array([4]),
      }]))).rejects.toThrow(/exact recovery policy binding/);
    await expect(vault.getBolt11Recovery(created.id)).resolves.toMatchObject({
      expectedScheme: 'cashu-bat',
    });
  });

  it('does not expose unlocked BOLT11 recovery mutation shortcuts', async () => {
    const vault = await AdmissionCredentialVaultV1.open();
    opened.push(vault);
    const surface = vault as unknown as Record<string, unknown>;
    expect(surface.updateBolt11Recovery).toBeUndefined();
    expect(surface.completeBolt11Acquisition).toBeUndefined();
    expect(typeof surface.withBolt11Recovery).toBe('function');
  });
});

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = fakeIndexedDB.deleteDatabase(databaseName);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(new Error('failed to delete admission test database'));
    request.onblocked = () => reject(new Error('admission test database deletion blocked'));
  });
}

async function createLegacyV2Database(): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = fakeIndexedDB.open(databaseName, 2);
    request.onupgradeneeded = () => {
      const openedDb = request.result;
      for (const name of [
        'meta',
        'records',
        'checkpoints',
        'quote-key-checkpoints',
        'bolt11-recovery',
      ]) {
        openedDb.createObjectStore(name, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('failed to create legacy admission database'));
  });
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(['records', 'bolt11-recovery'], 'readwrite');
    const legacy = { id: 'legacy', iv: new ArrayBuffer(12), ciphertext: new ArrayBuffer(16) };
    tx.objectStore('records').add(legacy);
    tx.objectStore('bolt11-recovery').add({ ...legacy, id: 'legacy-recovery' });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('failed to seed legacy admission database'));
    tx.onabort = () => reject(new Error('legacy admission seed transaction aborted'));
  });
  db.close();
}
