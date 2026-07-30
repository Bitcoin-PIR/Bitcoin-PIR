import { describe, expect, it } from 'vitest';

import { DirectoryRefreshIntentGuardV1 } from '../directory-refresh-intent.js';

const strictInput = {
  relayMode: 'strict-multi-relay' as const,
  relays: ['wss://one.example', 'wss://two.example'],
  pinnedDirectoryPubkeyHex: '11'.repeat(32),
};

describe('immutable directory refresh intent', () => {
  it('rejects old async/CAS completion after every security input changes', () => {
    for (const mutate of [
      (guard: DirectoryRefreshIntentGuardV1) => guard.invalidateInput(), // mode
      (guard: DirectoryRefreshIntentGuardV1) => guard.invalidateInput(), // relay set
      (guard: DirectoryRefreshIntentGuardV1) => guard.invalidateInput(), // key
      (guard: DirectoryRefreshIntentGuardV1) => guard.replaceBootstrap(),
    ]) {
      const guard = new DirectoryRefreshIntentGuardV1();
      const stale = guard.capture(strictInput);
      mutate(guard);
      expect(guard.isCurrent(stale, strictInput)).toBe(false);
    }
  });

  it('binds exact ordered relay, mode and key inputs even without an epoch change', () => {
    const guard = new DirectoryRefreshIntentGuardV1();
    const intent = guard.capture(strictInput);
    expect(guard.isCurrent(intent, strictInput)).toBe(true);
    expect(guard.isCurrent(intent, {
      ...strictInput,
      relayMode: 'centralized-single-relay',
      relays: ['wss://one.example'],
    })).toBe(false);
    expect(guard.isCurrent(intent, {
      ...strictInput,
      relays: [...strictInput.relays].reverse(),
    })).toBe(false);
    expect(guard.isCurrent(intent, {
      ...strictInput,
      pinnedDirectoryPubkeyHex: '22'.repeat(32),
    })).toBe(false);
  });

  it('freezes captured relay input against caller mutation', () => {
    const relays = [...strictInput.relays];
    const guard = new DirectoryRefreshIntentGuardV1();
    const intent = guard.capture({ ...strictInput, relays });
    relays[0] = 'wss://attacker.example';
    expect(intent.relays).toEqual(strictInput.relays);
    expect(Object.isFrozen(intent)).toBe(true);
    expect(Object.isFrozen(intent.relays)).toBe(true);
  });

  it('deterministically withholds a delayed CAS result after invalidation', async () => {
    const guard = new DirectoryRefreshIntentGuardV1();
    const intent = guard.capture(strictInput);
    let release!: (catalog: string) => void;
    const delayedCas = new Promise<string>((resolve) => { release = resolve; });
    let activeCatalog: string | null = null;
    const completion = delayedCas.then((catalog) => {
      if (guard.isCurrent(intent, strictInput)) activeCatalog = catalog;
    });
    guard.invalidateInput();
    release('stale-catalog');
    await completion;
    expect(activeCatalog).toBeNull();
  });
});
