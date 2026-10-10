/**
 * Fetch a proof artifact (a `/proofs/...` path on this origin). The caller
 * checks its hash and size.
 */
export async function fetchProofArtifactBytesV1(path: string): Promise<Uint8Array> {
  const response = await fetch(path, { credentials: 'omit', cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`failed to load ${path}: HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}
