import { describe, expect, it } from 'vitest';

import { NondecreasingUnixClockV1 } from '../trusted-time.js';

describe('page-wide trusted time floor', () => {
  it('never moves backwards and rejects an unavailable wall clock', () => {
    const clock = new NondecreasingUnixClockV1();
    expect(clock.sampleMilliseconds(2_500_999, 1_000)).toBe(2_500n);
    expect(clock.sampleMilliseconds(2_499_000, 1_500)).toBe(2_500n);
    expect(clock.sampleMilliseconds(2_501_000, 2_000)).toBe(2_501n);
    expect(() => clock.sampleMilliseconds(Number.NaN, 2_500)).toThrow(/unavailable/);
    expect(() => clock.sampleMilliseconds(0, 2_500)).toThrow(/unavailable/);
  });

  it('advances with page elapsed time when the wall clock stalls or rolls back', () => {
    const clock = new NondecreasingUnixClockV1();
    expect(clock.sampleMilliseconds(2_500_999, 1_000)).toBe(2_500n);
    expect(clock.sampleMilliseconds(2_400_000, 3_500)).toBe(2_502n);
    expect(() => clock.sampleMilliseconds(2_600_000, 999)).toThrow(/moved backwards/);
  });
});
