/**
 * One page-wide wall-clock plus monotonic-elapsed floor for validity checks.
 *
 * Browser wall time is not a cryptographic time oracle. Keeping the largest
 * observed Unix second and advancing the initial sample by page-local
 * performance time prevents a later wall-clock rollback or stall from making
 * already-expired credential or identity validity windows current.
 */
export class NondecreasingUnixClockV1 {
  private floor = 0n;
  private anchorWallUnix: bigint | null = null;
  private anchorMonotonicMilliseconds = 0;

  sampleMilliseconds(
    milliseconds: number,
    monotonicMilliseconds: number = globalThis.performance?.now() ?? Number.NaN,
  ): bigint {
    const wallMilliseconds = Math.floor(milliseconds);
    const monotonic = Math.floor(monotonicMilliseconds);
    if (!Number.isSafeInteger(wallMilliseconds) || wallMilliseconds <= 0
        || !Number.isSafeInteger(monotonic) || monotonic < 0) {
      throw new Error('trusted wall clock is unavailable');
    }
    const observed = BigInt(Math.floor(wallMilliseconds / 1000));
    if (this.anchorWallUnix === null) {
      this.anchorWallUnix = observed;
      this.anchorMonotonicMilliseconds = monotonic;
    }
    if (monotonic < this.anchorMonotonicMilliseconds) {
      throw new Error('trusted monotonic clock moved backwards');
    }
    const elapsedMilliseconds = monotonic - this.anchorMonotonicMilliseconds;
    if (!Number.isSafeInteger(elapsedMilliseconds)) {
      throw new Error('trusted monotonic clock is unavailable');
    }
    const elapsedUnix = BigInt(Math.floor(elapsedMilliseconds / 1000));
    const monotonicFloor = this.anchorWallUnix + elapsedUnix;
    if (observed > this.floor) this.floor = observed;
    if (monotonicFloor > this.floor) this.floor = monotonicFloor;
    return this.floor;
  }
}

const PAGE_CLOCK_V1 = new NondecreasingUnixClockV1();

/** Security-sensitive code in this page must use this shared clock. */
export function trustedNowUnixV1(): bigint {
  return PAGE_CLOCK_V1.sampleMilliseconds(Date.now());
}
