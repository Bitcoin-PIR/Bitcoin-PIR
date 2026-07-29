/**
 * Browser-local admission accounting for one deterministic backend plan.
 *
 * These counters must come from the backend planner that will emit the real
 * wire sequence. They are never inferred from the number of textarea rows:
 * DPF, Harmony, OnionPIR and ORAM deliberately account for logical work in
 * different units.
 */

import type {
  ServiceEntitlementLimitsViewV1,
  ServiceScopeViewV1,
} from './sdk-bridge.js';

export interface ProductQueryShapeV1 {
  backend: ServiceScopeViewV1['backend'];
  workload: ServiceScopeViewV1['workload'];
  /**
   * Planner-proven lower bounds. Omitted data-dependent counters remain
   * unknown; passing this check never claims that a complete query is
   * guaranteed to fit them.
   */
  lowerBounds: {
    logicalInputs?: number;
    frames?: number;
    requestBytes?: string;
    responseBytes?: string;
    wallTimeMs?: number;
    concurrentSockets?: number;
    hintGroups?: number;
    workUnits?: string;
  };
}

export type ProductQueryShapesByRoleV1 = Readonly<Record<string, ProductQueryShapeV1>>;

const U16_MAX = 0xffff;
const U32_MAX = 0xffff_ffff;
const U8_MAX = 0xff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Parse the complete signed EntitlementLimitsV1 JSON contract. */
export function canonicalServiceEntitlementLimitsV1(
  value: ServiceEntitlementLimitsViewV1,
  label = 'signed entitlement limits',
): ServiceEntitlementLimitsViewV1 {
  if (!value || typeof value !== 'object') throw new Error(`${label} are missing`);
  return {
    maxLogicalInputs: canonicalInteger(
      value.maxLogicalInputs, 0, U16_MAX, `${label}.maxLogicalInputs`,
    ),
    maxFrames: canonicalInteger(value.maxFrames, 1, U32_MAX, `${label}.maxFrames`),
    maxRequestBytes: canonicalU64(value.maxRequestBytes, `${label}.maxRequestBytes`),
    maxResponseBytes: canonicalU64(value.maxResponseBytes, `${label}.maxResponseBytes`),
    maxWallTimeMs: canonicalInteger(
      value.maxWallTimeMs, 1, U32_MAX, `${label}.maxWallTimeMs`,
    ),
    maxConcurrentSockets: canonicalInteger(
      value.maxConcurrentSockets, 1, U8_MAX, `${label}.maxConcurrentSockets`,
    ),
    maxHintGroups: canonicalInteger(
      value.maxHintGroups, 0, U16_MAX, `${label}.maxHintGroups`,
    ),
    maxWorkUnits: canonicalU64(value.maxWorkUnits, `${label}.maxWorkUnits`),
  };
}

/** Canonicalize a conservative demand emitted by an exact backend planner. */
export function canonicalProductQueryShapeV1(
  value: ProductQueryShapeV1,
  label = 'planned query shape',
): ProductQueryShapeV1 {
  if (!value || typeof value !== 'object') throw new Error(`${label} is missing`);
  if (!isBackend(value.backend) || !isWorkload(value.workload)) {
    throw new Error(`${label} has an unknown backend/workload`);
  }
  return {
    backend: value.backend,
    workload: value.workload,
    lowerBounds: canonicalDemandLowerBoundsV1(value.lowerBounds, label),
  };
}

/** Fail before acquisition or retirement if the exact signed scope is too small. */
export function assertProductQueryShapeFitsScopeV1(
  shapeValue: ProductQueryShapeV1,
  scope: ServiceScopeViewV1,
  label = 'selected service scope',
): void {
  const shape = canonicalProductQueryShapeV1(shapeValue);
  const limits = canonicalServiceEntitlementLimitsV1(scope.limits, `${label}.limits`);
  if (scope.backend !== shape.backend || scope.workload !== shape.workload) {
    throw new Error(`${label} does not match the planned backend/workload`);
  }
  const required = shape.lowerBounds;
  const comparisons: Array<[string, bigint | null, bigint]> = [
    ['logical inputs', optionalBigInt(required.logicalInputs), BigInt(limits.maxLogicalInputs)],
    ['frames', optionalBigInt(required.frames), BigInt(limits.maxFrames)],
    ['request bytes', optionalBigInt(required.requestBytes), BigInt(limits.maxRequestBytes)],
    ['response bytes', optionalBigInt(required.responseBytes), BigInt(limits.maxResponseBytes)],
    ['wall time', optionalBigInt(required.wallTimeMs), BigInt(limits.maxWallTimeMs)],
    ['concurrent sockets', optionalBigInt(required.concurrentSockets), BigInt(limits.maxConcurrentSockets)],
    ['hint groups', optionalBigInt(required.hintGroups), BigInt(limits.maxHintGroups)],
    ['work units', optionalBigInt(required.workUnits), BigInt(limits.maxWorkUnits)],
  ];
  for (const [field, required, maximum] of comparisons) {
    if (required !== null && required > maximum) {
      throw new Error(
        `${label} ${field} limit is insufficient (requires ${required}, signed maximum ${maximum})`,
      );
    }
  }
}

/**
 * A homogeneous pair may expose its common safe ceiling. Heterogeneous
 * Harmony hint/query legs deliberately return null because their counters use
 * different workload units and must be checked independently.
 */
export function intersectHomogeneousEntitlementLimitsV1(
  scopes: readonly ServiceScopeViewV1[],
): ServiceEntitlementLimitsViewV1 | null {
  if (scopes.length === 0) return null;
  const backend = scopes[0].backend;
  const workload = scopes[0].workload;
  if (scopes.some((scope) => scope.backend !== backend || scope.workload !== workload)) {
    return null;
  }
  const parsed = scopes.map((scope, index) =>
    canonicalServiceEntitlementLimitsV1(scope.limits, `scope[${index}].limits`));
  return parsed.slice(1).reduce<ServiceEntitlementLimitsViewV1>((left, right) => ({
    maxLogicalInputs: Math.min(left.maxLogicalInputs, right.maxLogicalInputs),
    maxFrames: Math.min(left.maxFrames, right.maxFrames),
    maxRequestBytes: minU64(left.maxRequestBytes, right.maxRequestBytes),
    maxResponseBytes: minU64(left.maxResponseBytes, right.maxResponseBytes),
    maxWallTimeMs: Math.min(left.maxWallTimeMs, right.maxWallTimeMs),
    maxConcurrentSockets: Math.min(left.maxConcurrentSockets, right.maxConcurrentSockets),
    maxHintGroups: Math.min(left.maxHintGroups, right.maxHintGroups),
    maxWorkUnits: minU64(left.maxWorkUnits, right.maxWorkUnits),
  }), { ...parsed[0] });
}

export function sameProductQueryShapeV1(
  left: ProductQueryShapeV1,
  right: ProductQueryShapeV1,
): boolean {
  const a = canonicalProductQueryShapeV1(left, 'stored planned query shape');
  const b = canonicalProductQueryShapeV1(right, 'current planned query shape');
  return a.backend === b.backend
    && a.workload === b.workload
    && JSON.stringify(a.lowerBounds) === JSON.stringify(b.lowerBounds);
}

function canonicalDemandLowerBoundsV1(
  value: ProductQueryShapeV1['lowerBounds'],
  label: string,
): ProductQueryShapeV1['lowerBounds'] {
  if (!value || typeof value !== 'object') throw new Error(`${label}.lowerBounds is missing`);
  const result: ProductQueryShapeV1['lowerBounds'] = {};
  if (value.logicalInputs !== undefined) {
    result.logicalInputs = canonicalInteger(
      value.logicalInputs, 0, U16_MAX, `${label}.lowerBounds.logicalInputs`,
    );
  }
  if (value.frames !== undefined) {
    result.frames = canonicalInteger(value.frames, 1, U32_MAX, `${label}.lowerBounds.frames`);
  }
  if (value.requestBytes !== undefined) {
    result.requestBytes = canonicalPositiveU64(
      value.requestBytes, `${label}.lowerBounds.requestBytes`,
    );
  }
  if (value.responseBytes !== undefined) {
    result.responseBytes = canonicalPositiveU64(
      value.responseBytes, `${label}.lowerBounds.responseBytes`,
    );
  }
  if (value.wallTimeMs !== undefined) {
    result.wallTimeMs = canonicalInteger(
      value.wallTimeMs, 1, U32_MAX, `${label}.lowerBounds.wallTimeMs`,
    );
  }
  if (value.concurrentSockets !== undefined) {
    result.concurrentSockets = canonicalInteger(
      value.concurrentSockets, 1, U8_MAX, `${label}.lowerBounds.concurrentSockets`,
    );
  }
  if (value.hintGroups !== undefined) {
    result.hintGroups = canonicalInteger(
      value.hintGroups, 0, U16_MAX, `${label}.lowerBounds.hintGroups`,
    );
  }
  if (value.workUnits !== undefined) {
    result.workUnits = canonicalPositiveU64(
      value.workUnits, `${label}.lowerBounds.workUnits`,
    );
  }
  if (Object.keys(result).length === 0) {
    throw new Error(`${label}.lowerBounds must contain planner-proven demand`);
  }
  return result;
}

function canonicalInteger(value: number, min: number, max: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${field} is outside its canonical integer range`);
  }
  return value;
}

function canonicalU64(value: string, field: string): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${field} must be a canonical decimal u64 string`);
  }
  const parsed = BigInt(value);
  if (parsed > U64_MAX) throw new Error(`${field} exceeds u64`);
  return parsed.toString();
}

function canonicalPositiveU64(value: string, field: string): string {
  const canonical = canonicalU64(value, field);
  if (canonical === '0') throw new Error(`${field} must be non-zero`);
  return canonical;
}

function minU64(left: string, right: string): string {
  return (BigInt(left) < BigInt(right) ? BigInt(left) : BigInt(right)).toString();
}

function optionalBigInt(value: number | string | undefined): bigint | null {
  return value === undefined ? null : BigInt(value);
}

function isBackend(value: string): value is ServiceScopeViewV1['backend'] {
  return value === 'dpf-pir' || value === 'harmony-pir'
    || value === 'onion-pir' || value === 'tee-oram';
}

function isWorkload(value: string): value is ServiceScopeViewV1['workload'] {
  return value === 'dpf-query' || value === 'harmony-hint'
    || value === 'harmony-query' || value === 'onion-session'
    || value === 'tee-oram-query';
}
