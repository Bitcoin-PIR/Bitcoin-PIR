import { describe, expect, it } from 'vitest';

import {
  assertProductQueryShapeFitsScopeV1,
  canonicalServiceEntitlementLimitsV1,
  intersectHomogeneousEntitlementLimitsV1,
  sameProductQueryShapeV1,
  type ProductQueryShapeV1,
} from '../service-entitlement.js';
import type { ServiceScopeViewV1 } from '../sdk-bridge.js';

const limits = {
  maxLogicalInputs: 3,
  maxFrames: 20,
  maxRequestBytes: '1000',
  maxResponseBytes: '2000',
  maxWallTimeMs: 3000,
  maxConcurrentSockets: 1,
  maxHintGroups: 40,
  maxWorkUnits: '5000',
};

function scope(
  workload: ServiceScopeViewV1['workload'] = 'dpf-query',
  overrides: Partial<typeof limits> = {},
): ServiceScopeViewV1 {
  return {
    scopeIdHex: '11'.repeat(32),
    backend: workload.startsWith('harmony') ? 'harmony-pir' : 'dpf-pir',
    workload,
    protocolVersion: workload.startsWith('harmony') ? 2 : 1,
    operationProfile: 1,
    entitlementProfile: 2,
    dataset: { kind: 'manifest-root', rootHex: '22'.repeat(32) },
    limits: { ...limits, ...overrides },
    offers: [],
  };
}

function shape(overrides: Partial<ProductQueryShapeV1['lowerBounds']> = {}): ProductQueryShapeV1 {
  return {
    backend: 'dpf-pir',
    workload: 'dpf-query',
    lowerBounds: {
      logicalInputs: 2,
      frames: 10,
      requestBytes: '900',
      concurrentSockets: 1,
      ...overrides,
    },
  };
}

describe('signed entitlement limits and planner lower bounds', () => {
  it('parses all counters canonically and rejects number-loss encodings', () => {
    expect(canonicalServiceEntitlementLimitsV1(limits)).toEqual(limits);
    expect(() => canonicalServiceEntitlementLimitsV1({
      ...limits,
      maxRequestBytes: '01',
    })).toThrow(/canonical decimal u64/);
    expect(() => canonicalServiceEntitlementLimitsV1({
      ...limits,
      maxFrames: 0,
    })).toThrow(/canonical integer range/);
  });

  it('rejects any planner-proven lower bound above its signed maximum', () => {
    expect(() => assertProductQueryShapeFitsScopeV1(shape(), scope())).not.toThrow();
    expect(() => assertProductQueryShapeFitsScopeV1(
      shape({ frames: 21 }),
      scope(),
    )).toThrow(/frames limit is insufficient/);
    expect(() => assertProductQueryShapeFitsScopeV1(
      shape({ requestBytes: '1001' }),
      scope(),
    )).toThrow(/request bytes limit is insufficient/);
  });

  it('does not pretend omitted data-dependent counters are guaranteed', () => {
    const lowerBoundOnly = shape();
    expect(lowerBoundOnly.lowerBounds.responseBytes).toBeUndefined();
    expect(() => assertProductQueryShapeFitsScopeV1(
      lowerBoundOnly,
      scope('dpf-query', { maxResponseBytes: '0', maxWorkUnits: '0' }),
    )).not.toThrow();
  });

  it('intersects only homogeneous workload units', () => {
    expect(intersectHomogeneousEntitlementLimitsV1([
      scope('dpf-query', { maxFrames: 20, maxRequestBytes: '1000' }),
      scope('dpf-query', { maxFrames: 8, maxRequestBytes: '1200' }),
    ])).toMatchObject({ maxFrames: 8, maxRequestBytes: '1000' });
    expect(intersectHomogeneousEntitlementLimitsV1([
      scope('harmony-hint'),
      scope('harmony-query'),
    ])).toBeNull();
  });

  it('compares canonical frozen shapes independent of caller object identity', () => {
    expect(sameProductQueryShapeV1(shape(), structuredClone(shape()))).toBe(true);
    expect(sameProductQueryShapeV1(shape(), shape({ frames: 11 }))).toBe(false);
  });
});
