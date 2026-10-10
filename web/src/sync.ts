/**
 * Client-side sync logic for multi-database PIR.
 *
 * Given a database catalog (full checkpoints + deltas) and the client's
 * last synced height, computes the optimal sync plan: either a single
 * full checkpoint or a chain of deltas to reach the latest tip.
 */

import type { DatabaseCatalog, DatabaseCatalogEntry } from './server-info.js';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SyncStep {
  dbId: number;
  dbType: 'full' | 'delta';
  name: string;
  baseHeight: number;
  tipHeight: number;
}

export interface SyncPlan {
  /** Ordered list of database queries to execute. */
  steps: SyncStep[];
  /** True if starting from scratch (no prior synced state). */
  isFreshSync: boolean;
  /** The height the client will be at after executing all steps. */
  targetHeight: number;
}

/** Maximum number of delta steps before we prefer a full checkpoint. */
const MAX_DELTA_CHAIN_LENGTH = 5;

// ─── Core ────────────────────────────────────────────────────────────────────

/**
 * Compute the optimal sync plan from the catalog.
 *
 * Strategy:
 *   1. If no lastSyncedHeight (or 0) → pick the highest full checkpoint.
 *   2. If already at the latest tip → empty plan.
 *   3. Try to find a chain of deltas from lastSyncedHeight to the latest tip.
 *   4. If no chain or chain too long → fall back to a fresh sync (step 1).
 *
 * Same plans as `pir_sdk::SyncPlanner::plan`.
 */
export function computeSyncPlan(
  catalog: DatabaseCatalog,
  lastSyncedHeight?: number,
): SyncPlan {
  if (catalog.databases.length === 0) {
    throw new Error('Empty catalog: no databases available');
  }

  const fullDbs = catalog.databases.filter(db => db.dbType === 0);
  const deltaDbs = catalog.databases.filter(db => db.dbType === 1);

  // Find the overall latest height (across all DBs)
  const latestTip = Math.max(
    ...fullDbs.map(db => db.height),
    ...deltaDbs.map(db => db.height),
  );

  // Helper to build a step from a catalog entry
  const toStep = (db: DatabaseCatalogEntry): SyncStep => ({
    dbId: db.dbId,
    dbType: db.dbType === 0 ? 'full' : 'delta',
    name: db.name,
    baseHeight: db.baseHeight,
    tipHeight: db.height,
  });

  // Find the best full checkpoint (highest height)
  const bestFull = fullDbs.length > 0
    ? fullDbs.reduce((best, db) => db.height > best.height ? db : best)
    : null;

  // Fresh sync: the best full checkpoint, plus a delta chain from it to
  // the tip when one exists.
  const freshSyncPlan = (): SyncPlan => {
    if (!bestFull) {
      throw new Error('No full checkpoint available for fresh sync');
    }
    const steps: SyncStep[] = [toStep(bestFull)];
    if (bestFull.height < latestTip) {
      const tail = findDeltaChain(deltaDbs, bestFull.height, latestTip);
      if (tail) steps.push(...tail.map(toStep));
    }
    return {
      steps,
      isFreshSync: true,
      targetHeight: steps[steps.length - 1].tipHeight,
    };
  };

  if (!lastSyncedHeight) return freshSyncPlan();

  // ── Already at tip ─────────────────────────────────────────────────
  if (lastSyncedHeight >= latestTip) {
    return {
      steps: [],
      isFreshSync: false,
      targetHeight: lastSyncedHeight,
    };
  }

  // ── Try delta chain ────────────────────────────────────────────────
  const chain = findDeltaChain(deltaDbs, lastSyncedHeight, latestTip);
  if (chain) {
    return {
      steps: chain.map(toStep),
      isFreshSync: false,
      targetHeight: latestTip,
    };
  }

  return freshSyncPlan();
}

// ─── Delta chain search ──────────────────────────────────────────────────────

/**
 * Find the shortest chain of deltas from `fromHeight` to `toHeight` (BFS).
 * Returns the ordered delta catalog entries, or null if no chain of at most
 * `MAX_DELTA_CHAIN_LENGTH` steps exists.
 */
function findDeltaChain(
  deltas: DatabaseCatalogEntry[],
  fromHeight: number,
  toHeight: number,
): DatabaseCatalogEntry[] | null {
  // Index deltas by baseHeight for O(1) lookup
  const byBase = new Map<number, DatabaseCatalogEntry[]>();
  for (const d of deltas) {
    const list = byBase.get(d.baseHeight) ?? [];
    list.push(d);
    byBase.set(d.baseHeight, list);
  }

  // BFS
  interface QueueItem {
    height: number;
    path: DatabaseCatalogEntry[];
  }
  const queue: QueueItem[] = [{ height: fromHeight, path: [] }];
  const visited = new Set<number>([fromHeight]);

  while (queue.length > 0) {
    const { height, path } = queue.shift()!;

    const nexts = byBase.get(height);
    if (!nexts) continue;

    for (const d of nexts) {
      if (visited.has(d.height)) continue;
      visited.add(d.height);

      const newPath = [...path, d];
      if (d.height === toHeight) {
        return newPath;
      }
      // Don't explore further if chain is already too long
      if (newPath.length < MAX_DELTA_CHAIN_LENGTH) {
        queue.push({ height: d.height, path: newPath });
      }
    }
  }

  return null;
}
