import { describe, expect, it } from 'vitest';

import { directoryRefreshFailureStateV1 } from '../directory-refresh-status.js';

describe('directory refresh failure assurance', () => {
  it('retains and visibly labels a previously verified centralized catalog', () => {
    const state = directoryRefreshFailureStateV1({
      directoryMode: 'centralized-single-relay',
      directoryAssurance: 'centralized-degraded-no-relay-cross-check',
    }, 'centralized-single-relay');

    expect(state.retainCatalog).toBe(true);
    expect(state.statusText).toMatch(/centralized\/degraded/i);
    expect(state.statusText).toMatch(/no relay split-view or outage cross-check/i);
    expect(state.statusText).toMatch(/no automatic retry/i);
  });

  it('retains and labels a previously verified strict multi-relay catalog', () => {
    const state = directoryRefreshFailureStateV1({
      directoryMode: 'strict-multi-relay',
      directoryAssurance: 'multi-origin-split-view-compared',
    }, 'strict-multi-relay');

    expect(state.retainCatalog).toBe(true);
    expect(state.statusText).toMatch(/strict multi-relay/i);
    expect(state.statusText).toMatch(/no automatic retry/i);
    expect(state.statusText).not.toMatch(/centralized\/degraded/i);
  });

  it('clears absent, inconsistent, or unknown retained assurance state', () => {
    expect(directoryRefreshFailureStateV1(null, 'strict-multi-relay').retainCatalog).toBe(false);
    expect(directoryRefreshFailureStateV1({
      directoryMode: 'strict-multi-relay',
      directoryAssurance: 'centralized-degraded-no-relay-cross-check',
    }, 'strict-multi-relay').retainCatalog).toBe(false);
    expect(directoryRefreshFailureStateV1({
      directoryMode: 'centralized-single-relay',
      directoryAssurance: 'centralized-degraded-no-relay-cross-check',
    }, 'strict-multi-relay').retainCatalog).toBe(false);
    const unknown = directoryRefreshFailureStateV1({
      directoryMode: 'future-mode',
      directoryAssurance: 'future-assurance',
    }, 'future-mode');
    expect(unknown.retainCatalog).toBe(false);
    expect(unknown.statusText).toMatch(/admission stays fail closed/i);
  });
});
