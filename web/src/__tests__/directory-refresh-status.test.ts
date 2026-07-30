import { describe, expect, it } from 'vitest';

import { directoryRefreshFailureStateV1 } from '../directory-refresh-status.js';
import { assertSelectableDirectoryCatalogFreshV1 } from '../directory-vault.js';

describe('directory refresh failure assurance', () => {
  it('retains and visibly labels a previously verified centralized catalog', () => {
    const state = directoryRefreshFailureStateV1({
      directoryMode: 'centralized-single-relay',
      directoryAssurance: 'centralized-degraded-no-relay-cross-check',
      catalogValidUntilUnix: '2500',
    }, 'centralized-single-relay', 1_500n);

    expect(state.retainCatalog).toBe(true);
    expect(state.statusText).toMatch(/centralized\/degraded/i);
    expect(state.statusText).toMatch(/no relay split-view or outage cross-check/i);
    expect(state.statusText).toMatch(/no automatic retry/i);
  });

  it('retains and labels a previously verified strict multi-relay catalog', () => {
    const state = directoryRefreshFailureStateV1({
      directoryMode: 'strict-multi-relay',
      directoryAssurance: 'multi-origin-split-view-compared',
      catalogValidUntilUnix: '2500',
    }, 'strict-multi-relay', 1_500n);

    expect(state.retainCatalog).toBe(true);
    expect(state.statusText).toMatch(/strict multi-relay/i);
    expect(state.statusText).toMatch(/no automatic retry/i);
    expect(state.statusText).not.toMatch(/centralized\/degraded/i);
  });

  it('clears absent, inconsistent, or unknown retained assurance state', () => {
    expect(directoryRefreshFailureStateV1(null, 'strict-multi-relay', 1_500n).retainCatalog)
      .toBe(false);
    expect(directoryRefreshFailureStateV1({
      directoryMode: 'strict-multi-relay',
      directoryAssurance: 'centralized-degraded-no-relay-cross-check',
      catalogValidUntilUnix: '2500',
    }, 'strict-multi-relay', 1_500n).retainCatalog).toBe(false);
    expect(directoryRefreshFailureStateV1({
      directoryMode: 'centralized-single-relay',
      directoryAssurance: 'centralized-degraded-no-relay-cross-check',
      catalogValidUntilUnix: '2500',
    }, 'strict-multi-relay', 1_500n).retainCatalog).toBe(false);
    const unknown = directoryRefreshFailureStateV1({
      directoryMode: 'future-mode',
      directoryAssurance: 'future-assurance',
      catalogValidUntilUnix: '2500',
    }, 'future-mode', 1_500n);
    expect(unknown.retainCatalog).toBe(false);
    expect(unknown.statusText).toMatch(/admission stays fail closed/i);
  });

  it('never retains an expired catalog after a refresh failure', () => {
    const state = directoryRefreshFailureStateV1({
      directoryMode: 'strict-multi-relay',
      directoryAssurance: 'multi-origin-split-view-compared',
      catalogValidUntilUnix: '2500',
    }, 'strict-multi-relay', 2_501n);
    expect(state.retainCatalog).toBe(false);
    expect(state.statusText).toMatch(/no previously verified directory catalog/i);
  });

  it('fails closed immediately after the conservative authenticated expiry', () => {
    const catalog = {
      version: 1 as const,
      directoryPubkeyHex: '11'.repeat(32),
      directoryMode: 'centralized-single-relay' as const,
      directoryAssurance: 'centralized-degraded-no-relay-cross-check' as const,
      catalogValidUntilUnix: '2500',
      shards: [],
    };
    expect(() => assertSelectableDirectoryCatalogFreshV1(catalog, 2_500n)).not.toThrow();
    expect(() => assertSelectableDirectoryCatalogFreshV1(catalog, 2_501n))
      .toThrow(/expired/);
  });
});
