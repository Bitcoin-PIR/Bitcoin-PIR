/**
 * Reload once when a lazy chunk from an older build is gone.
 *
 * Every Pages deploy replaces the hashed assets. A page loaded before the
 * deploy — or from a cached `index.html` (Pages serves `max-age=600`) —
 * still references the previous chunk names, so its first lazy import (for
 * example the Cashu library at the start of a credit purchase) fails with
 * "Failed to fetch dynamically imported module". Vite reports that as a
 * cancelable `vite:preloadError` event on `window`. Reloading revalidates
 * `index.html` and picks up the new build; state that matters (stored
 * credentials, a pending purchase) lives in `localStorage` and survives.
 *
 * A second failure within `STALE_CHUNK_RELOAD_WINDOW_MS` is not a stale page
 * but a broken deploy: the event is left alone so the error surfaces instead
 * of reloading in a loop.
 */

export const STALE_CHUNK_RELOAD_KEY = 'bitcoinpir.stale-chunk-reload-at';
export const STALE_CHUNK_RELOAD_WINDOW_MS = 60_000;

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export interface StaleChunkReloadEnv {
  storage: StorageLike | null;
  now(): number;
  reload(): void;
}

function defaultEnv(): StaleChunkReloadEnv {
  let storage: StorageLike | null = null;
  try {
    storage = (globalThis as { sessionStorage?: StorageLike }).sessionStorage ?? null;
  } catch {
    storage = null;
  }
  return {
    storage,
    now: () => Date.now(),
    reload: () => (globalThis as { location?: { reload(): void } }).location?.reload(),
  };
}

/**
 * Record a reload attempt and say whether to reload now: no when a reload
 * already happened within the window, or when the attempt cannot be
 * recorded (without the record a broken deploy would loop).
 */
export function claimStaleChunkReload(env: StaleChunkReloadEnv): boolean {
  if (!env.storage) return false;
  const now = env.now();
  try {
    const last = Number(env.storage.getItem(STALE_CHUNK_RELOAD_KEY));
    if (Number.isFinite(last) && last > 0 && now - last < STALE_CHUNK_RELOAD_WINDOW_MS) return false;
    env.storage.setItem(STALE_CHUNK_RELOAD_KEY, String(now));
    return true;
  } catch {
    return false;
  }
}

/** Listen for `vite:preloadError` on `target` (the page's `window`). */
export function installStaleChunkReload(
  target: EventTarget = globalThis as unknown as EventTarget,
  env: StaleChunkReloadEnv = defaultEnv(),
): void {
  target.addEventListener('vite:preloadError', (event) => {
    if (!claimStaleChunkReload(env)) return;
    event.preventDefault();
    env.reload();
  });
}
