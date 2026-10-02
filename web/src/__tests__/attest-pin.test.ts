import { describe, expect, it, vi } from 'vitest';

import {
  AMD_MILAN_ARK_FINGERPRINT,
  AMD_MILAN_ARK_FINGERPRINT_HEX,
  AMD_TURIN_ARK_FINGERPRINT,
  applySevSnpPlatformFloor,
  pinAcceptsBinary,
} from '../attest-pin.js';

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

describe('applySevSnpPlatformFloor', () => {
  const policy = () => ({
    setMinTcb: vi.fn(),
    setRequireAliasCheckComplete: vi.fn(),
    setRequiredMitVectorBits: vi.fn(),
  });

  it('holds reports chained to the Milan ARK to the Milan floor', () => {
    expect(Array.from(AMD_MILAN_ARK_FINGERPRINT, (b) => b.toString(16).padStart(2, '0')).join(''))
      .toBe(AMD_MILAN_ARK_FINGERPRINT_HEX);
    const p = policy();
    applySevSnpPlatformFloor(p, AMD_MILAN_ARK_FINGERPRINT);
    expect(p.setMinTcb).toHaveBeenCalledWith(4, 0, 29, 222);
    expect(p.setRequireAliasCheckComplete).toHaveBeenCalledWith(true);
    expect(p.setRequiredMitVectorBits).toHaveBeenCalledWith(0b10);
  });

  it('leaves the Turin and unpinned policies unchanged', () => {
    for (const ark of [AMD_TURIN_ARK_FINGERPRINT, null, undefined]) {
      const p = policy();
      applySevSnpPlatformFloor(p, ark);
      expect(p.setMinTcb).not.toHaveBeenCalled();
      expect(p.setRequireAliasCheckComplete).not.toHaveBeenCalled();
      expect(p.setRequiredMitVectorBits).not.toHaveBeenCalled();
    }
  });
});
