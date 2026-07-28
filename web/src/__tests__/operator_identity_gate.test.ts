import { describe, it, expect } from 'vitest';
import {
  gateOperatorIdentity,
  resolveIndependentOperatorPinsV1,
} from '../dpf-adapter.js';
import type { WasmAnnounceVerification } from '../sdk-bridge.js';

/**
 * Minimal fake of the WASM bundle handle. Only `checkPinnedOperator` /
 * `checkChannelBinding` behaviour matters — they throw (as the real
 * wasm-bindgen methods do) when `throwOn` selects them. The getters
 * stand in for a parsed bundle so we can assert the surfaced fields.
 */
function fakeBundle(throwOn?: 'operator' | 'channel' | 'freshness'): WasmAnnounceVerification {
  return {
    serverId: 'pir1',
    operatorPubkeyHex: '47d98cb6'.padEnd(64, '0'),
    identityPubkeyHex: 'dbefff8b'.padEnd(64, '0'),
    channelPub: new Uint8Array(32),
    channelPubHex: '0'.repeat(64),
    binarySha256Hex: '0'.repeat(64),
    gitRev: 'test-rev',
    validFrom: 0n,
    validUntil: 1811051894n,
    issuedAt: 1779515936n,
    chainVerified: true,
    chainError: '',
    checkPinnedOperator() {
      if (throwOn === 'operator') {
        throw new Error(
          'announce: cert.operator_pubkey (aa…) does not match pinned operator (bb…)',
        );
      }
    },
    checkChannelBinding() {
      if (throwOn === 'channel') {
        throw new Error(
          'announce: bundle channel_pub (aa…) does not match the handshake key (bb…)',
        );
      }
    },
    checkFreshness() {
      if (throwOn === 'freshness') {
        throw new Error('announce: manifest issued_at (…) is 99999s old, exceeds max age 1s');
      }
    },
    free() {},
  } as unknown as WasmAnnounceVerification;
}

const PIN = new Uint8Array(32);
const CHANNEL = new Uint8Array(32);

describe('gateOperatorIdentity', () => {
  it("returns 'verified' with bundle fields when both checks pass", () => {
    const r = gateOperatorIdentity(fakeBundle(), PIN, CHANNEL, 0n);
    expect(r.state).toBe('verified');
    expect(r.serverId).toBe('pir1');
    expect(r.binarySha256Hex).toBe('0'.repeat(64));
    expect(r.gitRev).toBe('test-rev');
    expect(r.validUntil).toBe(1811051894); // bigint → number
    expect(r.error).toBeUndefined();
  });

  it("returns 'unverified' when the operator-pin check throws", () => {
    const r = gateOperatorIdentity(fakeBundle('operator'), PIN, CHANNEL, 0n);
    expect(r.state).toBe('unverified');
    expect(r.error).toMatch(/does not match pinned operator/);
    // best-effort identifying fields still surfaced for diagnostics
    expect(r.serverId).toBe('pir1');
  });

  it("returns 'unverified' when the channel-binding check throws", () => {
    const r = gateOperatorIdentity(fakeBundle('channel'), PIN, CHANNEL, 0n);
    expect(r.state).toBe('unverified');
    expect(r.error).toMatch(/does not match the handshake key/);
  });

  it("returns 'unverified' when the freshness check throws (stale bundle)", () => {
    const r = gateOperatorIdentity(fakeBundle('freshness'), PIN, CHANNEL, 1_700_000_000n, 1n);
    expect(r.state).toBe('unverified');
    expect(r.error).toMatch(/exceeds max age/);
  });

  it('requires two distinct explicit pins in strict mode and ignores the legacy shared pin', () => {
    const first = new Uint8Array(32).fill(1);
    const second = new Uint8Array(32).fill(2);
    const legacy = new Uint8Array(32).fill(3);
    expect(resolveIndependentOperatorPinsV1({
      strictVerification: true,
      first,
      second,
      legacyShared: legacy,
    })).toEqual([first, second]);
    expect(() => resolveIndependentOperatorPinsV1({
      strictVerification: true,
      legacyShared: legacy,
    })).toThrow(/first operator pin/);
    expect(() => resolveIndependentOperatorPinsV1({
      strictVerification: true,
      first,
      second: first.slice(),
      legacyShared: legacy,
    })).toThrow(/distinct operator pins/);
  });

  it('marks a swapped per-leg pin unverified', () => {
    const expected = new Uint8Array(32).fill(1);
    const swapped = new Uint8Array(32).fill(2);
    const bundle = fakeBundle();
    bundle.checkPinnedOperator = (pin: Uint8Array) => {
      if (!pin.every((byte) => byte === 1)) throw new Error('wrong per-leg operator pin');
    };
    expect(gateOperatorIdentity(bundle, expected, CHANNEL, 0n).state).toBe('verified');
    expect(gateOperatorIdentity(bundle, swapped, CHANNEL, 0n)).toMatchObject({
      state: 'unverified',
      error: 'wrong per-leg operator pin',
    });
  });
});
