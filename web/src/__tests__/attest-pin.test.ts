import { describe, expect, it } from 'vitest';

import { pinAcceptsBinary } from '../attest-pin.js';

describe('pinAcceptsBinary', () => {
  it('accepts only the pinned build when no transition is set', () => {
    const pin = { binarySha256Hex: 'aa'.repeat(32) };
    expect(pinAcceptsBinary(pin, 'aa'.repeat(32))).toBe(true);
    expect(pinAcceptsBinary(pin, 'AA'.repeat(32))).toBe(true);
    expect(pinAcceptsBinary(pin, 'bb'.repeat(32))).toBe(false);
  });

  it('accepts the transition build as well while a switch is in progress', () => {
    const pin = { binarySha256Hex: 'aa'.repeat(32), transitionBinarySha256Hex: 'bb'.repeat(32) };
    expect(pinAcceptsBinary(pin, 'aa'.repeat(32))).toBe(true);
    expect(pinAcceptsBinary(pin, 'bb'.repeat(32))).toBe(true);
    expect(pinAcceptsBinary(pin, 'cc'.repeat(32))).toBe(false);
  });

  it('never accepts on an empty pin', () => {
    expect(pinAcceptsBinary({}, '')).toBe(false);
    expect(pinAcceptsBinary({ binarySha256Hex: '', transitionBinarySha256Hex: ' ' }, '')).toBe(false);
  });
});
