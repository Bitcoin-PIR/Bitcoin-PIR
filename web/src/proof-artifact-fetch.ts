const PROOF_PATH = /^\/proofs\/[A-Za-z0-9._/-]+$/;
const DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;

export interface ProofArtifactFetchOptionsV1 {
  baseHref?: string;
  fetchImpl?: typeof fetch;
  maxBytes?: number;
}

/** Resolve a manifest-controlled artifact path without permitting an SSRF-like request. */
export function resolveProofArtifactUrlV1(path: string, baseHref?: string): URL {
  if (typeof path !== 'string' || !PROOF_PATH.test(path)) {
    throw new Error('proof artifact path must be a canonical absolute /proofs/ path');
  }
  if (path.includes('//') || path.split('/').some((segment) => segment === '.' || segment === '..')) {
    throw new Error('proof artifact path contains a non-canonical segment');
  }

  const effectiveBase = baseHref ?? globalThis.location?.href;
  if (!effectiveBase) throw new Error('proof artifact fetch has no browser origin');
  const base = new URL(effectiveBase);
  const resolved = new URL(path, base);
  if ((base.protocol !== 'https:' && base.protocol !== 'http:')
      || resolved.origin !== base.origin
      || resolved.protocol !== base.protocol
      || resolved.username
      || resolved.password
      || resolved.search
      || resolved.hash
      || resolved.pathname !== path) {
    throw new Error('proof artifact path escaped the current origin or /proofs/ namespace');
  }
  return resolved;
}

/**
 * Fetch a proof artifact with no ambient credentials, no referrer, and no
 * redirects. Artifact hashes and exact sizes are still checked by the caller.
 */
export async function fetchProofArtifactBytesV1(
  path: string,
  options: ProofArtifactFetchOptionsV1 = {},
): Promise<Uint8Array> {
  const url = resolveProofArtifactUrlV1(path, options.baseHref);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('proof artifact fetch is unavailable');
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_ARTIFACT_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error('proof artifact maxBytes must be a positive safe integer');
  }

  const response = await fetchImpl(url.href, {
    method: 'GET',
    mode: 'same-origin',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });
  if (response.redirected || (response.url && response.url !== url.href)) {
    throw new Error(`proof artifact redirect rejected for ${path}`);
  }
  if (!response.ok) {
    throw new Error(`failed to load ${path}: HTTP ${response.status}`);
  }
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null) {
    const declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength < 0 || declaredLength > maxBytes) {
      throw new Error(`proof artifact ${path} exceeds the ${maxBytes}-byte fetch limit`);
    }
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > maxBytes) {
    throw new Error(`proof artifact ${path} exceeds the ${maxBytes}-byte fetch limit`);
  }
  return bytes;
}
