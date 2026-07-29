/**
 * Hold PIR results behind the inclusion-verification boundary.
 *
 * Callers must invoke this before rendering, caching, merging, or exposing
 * inspector data. A missing result/trace, verifier length skew, thrown
 * verifier error, or any non-true verdict rejects the whole batch.
 */
export async function requireVerifiedQueryResultsV1<
  T extends { allIndexBins?: readonly unknown[] },
>(
  results: readonly (T | null | undefined)[],
  verify: (concrete: T[]) => Promise<readonly boolean[]>,
  label: string,
): Promise<T[]> {
  if (results.length === 0) {
    throw new Error(`${label} returned an empty result batch`);
  }
  const concrete: T[] = [];
  for (let index = 0; index < results.length; index++) {
    const result = results[index];
    if (!result || !Array.isArray(result.allIndexBins) || result.allIndexBins.length === 0) {
      throw new Error(`${label} result ${index} has no verifiable INDEX trace`);
    }
    concrete.push(result);
  }
  const verdicts = await verify(concrete);
  if (verdicts.length !== concrete.length) {
    throw new Error(
      `${label} verifier returned ${verdicts.length} verdicts for ${concrete.length} results`,
    );
  }
  const failed = verdicts.findIndex((verdict) => verdict !== true);
  if (failed !== -1) {
    throw new Error(`${label} inclusion verification failed for result ${failed}`);
  }
  return concrete;
}
