import { describe, expect, it, vi } from 'vitest';
import {
  STALE_CHUNK_RELOAD_KEY,
  STALE_CHUNK_RELOAD_WINDOW_MS,
  claimStaleChunkReload,
  installStaleChunkReload,
  type StaleChunkReloadEnv,
} from '../stale-chunk-reload.js';

function memoryEnv(start = 1_000_000): StaleChunkReloadEnv & { clock: { t: number }; map: Map<string, string> } {
  const map = new Map<string, string>();
  const clock = { t: start };
  return {
    map,
    clock,
    storage: {
      getItem: (key) => map.get(key) ?? null,
      setItem: (key, value) => { map.set(key, value); },
    },
    now: () => clock.t,
    reload: vi.fn(),
  };
}

function preloadError(): Event {
  return new Event('vite:preloadError', { cancelable: true });
}

describe('stale chunk reload', () => {
  it('reloads once on a failed lazy import and cancels the error', () => {
    const target = new EventTarget();
    const env = memoryEnv();
    installStaleChunkReload(target, env);

    const event = preloadError();
    target.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(env.reload).toHaveBeenCalledOnce();
    expect(env.map.get(STALE_CHUNK_RELOAD_KEY)).toBe(String(env.clock.t));
  });

  it('lets a second failure within the window surface instead of looping', () => {
    const target = new EventTarget();
    const env = memoryEnv();
    installStaleChunkReload(target, env);
    target.dispatchEvent(preloadError());

    env.clock.t += STALE_CHUNK_RELOAD_WINDOW_MS - 1;
    const again = preloadError();
    target.dispatchEvent(again);

    expect(again.defaultPrevented).toBe(false);
    expect(env.reload).toHaveBeenCalledOnce();
  });

  it('reloads again once the window has passed', () => {
    const env = memoryEnv();
    expect(claimStaleChunkReload(env)).toBe(true);
    env.clock.t += STALE_CHUNK_RELOAD_WINDOW_MS;
    expect(claimStaleChunkReload(env)).toBe(true);
  });

  it('never reloads when the attempt cannot be recorded', () => {
    const target = new EventTarget();
    const env = { ...memoryEnv(), storage: null };
    installStaleChunkReload(target, env);
    const event = preloadError();
    target.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
    expect(env.reload).not.toHaveBeenCalled();

    const throwing = memoryEnv();
    throwing.storage = {
      getItem: () => { throw new Error('storage blocked'); },
      setItem: () => { throw new Error('storage blocked'); },
    };
    expect(claimStaleChunkReload(throwing)).toBe(false);
  });
});
