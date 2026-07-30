import type { DirectoryRelayModeV1 } from './nostr-directory.js';

export interface DirectoryRefreshInputV1 {
  relayMode: DirectoryRelayModeV1;
  relays: readonly string[];
  pinnedDirectoryPubkeyHex: string;
}

export interface DirectoryRefreshIntentV1 extends DirectoryRefreshInputV1 {
  readonly generation: number;
  readonly bootstrapRevision: number;
}

/**
 * Page-local epoch guard for directory refreshes.  The relay set, mode, key,
 * and trusted-bootstrap revision form one immutable intent; a durable CAS may
 * finish after invalidation, but its stale result can never become active.
 */
export class DirectoryRefreshIntentGuardV1 {
  private generation = 0;
  private bootstrapRevision = 0;

  invalidateInput(): void {
    this.generation += 1;
  }

  replaceBootstrap(): void {
    this.bootstrapRevision += 1;
    this.generation += 1;
  }

  capture(input: DirectoryRefreshInputV1): DirectoryRefreshIntentV1 {
    const canonical = canonicalInput(input);
    return Object.freeze({
      ...canonical,
      relays: Object.freeze(canonical.relays.slice()),
      generation: this.generation,
      bootstrapRevision: this.bootstrapRevision,
    });
  }

  isCurrent(intent: DirectoryRefreshIntentV1, input: DirectoryRefreshInputV1): boolean {
    const current = canonicalInput(input);
    return intent.generation === this.generation
      && intent.bootstrapRevision === this.bootstrapRevision
      && intent.relayMode === current.relayMode
      && intent.pinnedDirectoryPubkeyHex === current.pinnedDirectoryPubkeyHex
      && intent.relays.length === current.relays.length
      && intent.relays.every((relay, index) => relay === current.relays[index]);
  }
}

function canonicalInput(input: DirectoryRefreshInputV1): DirectoryRefreshInputV1 {
  if (input.relayMode !== 'strict-multi-relay'
      && input.relayMode !== 'centralized-single-relay') {
    throw new Error('directory refresh intent has an unsupported mode');
  }
  if (!Array.isArray(input.relays) || input.relays.some((relay) => typeof relay !== 'string')) {
    throw new Error('directory refresh intent has an invalid relay set');
  }
  if (typeof input.pinnedDirectoryPubkeyHex !== 'string') {
    throw new Error('directory refresh intent has an invalid key');
  }
  return {
    relayMode: input.relayMode,
    relays: input.relays.map((relay) => relay.trim()).filter(Boolean),
    pinnedDirectoryPubkeyHex: input.pinnedDirectoryPubkeyHex.trim(),
  };
}
