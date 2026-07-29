export interface RetainedDirectoryCatalogAssuranceV1 {
  directoryMode: string;
  directoryAssurance: string;
}

export interface DirectoryRefreshFailureStateV1 {
  retainCatalog: boolean;
  statusText: string;
}

/**
 * Preserve the assurance label together with any catalog that remains usable
 * after a failed refresh. An impossible or future mode/assurance combination
 * is cleared instead of being displayed under the wrong trust label.
 */
export function directoryRefreshFailureStateV1(
  catalog: RetainedDirectoryCatalogAssuranceV1 | null,
  attemptedMode: string,
): DirectoryRefreshFailureStateV1 {
  if (
    attemptedMode === 'centralized-single-relay'
    && catalog?.directoryMode === 'centralized-single-relay'
    && catalog.directoryAssurance === 'centralized-degraded-no-relay-cross-check'
  ) {
    return {
      retainCatalog: true,
      statusText: 'Directory refresh rejected; the last verified catalog remains centralized/degraded, with no relay split-view or outage cross-check. There is no automatic retry.',
    };
  }
  if (
    attemptedMode === 'strict-multi-relay'
    && catalog?.directoryMode === 'strict-multi-relay'
    && catalog.directoryAssurance === 'multi-origin-split-view-compared'
  ) {
    return {
      retainCatalog: true,
      statusText: 'Directory refresh rejected; the last verified strict multi-relay catalog remains in use. There is no automatic retry.',
    };
  }
  return {
    retainCatalog: false,
    statusText: 'Directory refresh rejected; no previously verified directory catalog remains usable. The trusted bootstrap remains and admission stays fail closed, with no automatic retry.',
  };
}
