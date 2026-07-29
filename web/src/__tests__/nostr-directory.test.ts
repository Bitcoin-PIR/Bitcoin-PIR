import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const candidate = {
    free: vi.fn(),
    stateKeysJson: vi.fn(),
    prepareRollback: vi.fn(),
    acknowledgePersisted: vi.fn(),
    selectableCatalogJson: vi.fn(),
  };
  return {
    candidate,
    verifyRelayCatalogs: vi.fn(() => candidate),
    verifyCentralizedSingleRelayCatalog: vi.fn(() => candidate),
  };
});

vi.mock('../sdk-bridge.js', () => ({
  requireSdkWasm: () => ({
    directoryFullCatalogReqJsonV1: () => JSON.stringify(
      Array.from({ length: 16 }, (_, shard) => [
        'REQ',
        `bitcoinpir-directory-v1-shard-${shard.toString(16)}`,
        { authors: ['11'.repeat(32)], kinds: [30078] },
      ]),
    ),
    WasmDirectoryCatalogCandidateV1: {
      verifyRelayCatalogs: mocks.verifyRelayCatalogs,
      verifyCentralizedSingleRelayCatalog: mocks.verifyCentralizedSingleRelayCatalog,
    },
  }),
}));

import type {
  DirectoryRollbackVaultV1,
  SelectableDirectoryCatalogV1,
} from '../directory-vault.js';
import {
  type DirectoryWebSocketV1,
  refreshNostrDirectoryV1,
} from '../nostr-directory.js';

const directoryPubkey = '11'.repeat(32);
const selectable = {
  version: 1 as const,
  directoryPubkeyHex: directoryPubkey,
  directoryMode: 'strict-multi-relay' as const,
  directoryAssurance: 'multi-origin-split-view-compared' as const,
  shards: Array.from({ length: 16 }, (_, shard) => ({
    shard,
    checkpointEpoch: '1',
    checkpointRootHex: '22'.repeat(32),
    entries: [],
  })),
};

const centralizedSelectable = {
  ...selectable,
  directoryMode: 'centralized-single-relay' as const,
  directoryAssurance: 'centralized-degraded-no-relay-cross-check' as const,
};

class MockRelay implements DirectoryWebSocketV1 {
  readonly readyState = 1;
  readonly sent: string[] = [];
  closeCalls = 0;
  private readonly listeners = new Map<string, Set<(event: any) => void>>();

  constructor(
    private readonly marker: string,
    private readonly missingEoseShard: number | null = null,
    private readonly floodFirstShard = false,
  ) {
    queueMicrotask(() => this.emit('open', new Event('open')));
  }

  send(data: string): void {
    this.sent.push(data);
    const parsed = JSON.parse(data) as unknown[];
    if (parsed[0] !== 'REQ') return;
    const subscription = String(parsed[1]);
    const shard = Number.parseInt(subscription.slice(-1), 16);
    queueMicrotask(() => {
      const count = this.floodFirstShard && shard === 0 ? 33 : 1;
      for (let index = 0; index < count; index += 1) {
        this.emit('message', new MessageEvent('message', {
          data: JSON.stringify(['EVENT', subscription, {
            marker: this.floodFirstShard ? 'x'.repeat(255 * 1024) : this.marker,
            shard,
            index,
          }]),
        }));
      }
      if (shard !== this.missingEoseShard) {
        this.emit('message', new MessageEvent('message', {
          data: JSON.stringify(['EOSE', subscription]),
        }));
      }
    });
  }

  close(): void { this.closeCalls += 1; }

  addEventListener(type: string, listener: (event: any) => void): void {
    const listeners = this.listeners.get(type) ?? new Set();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: string, listener: (event: any) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  private emit(type: string, event: any): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

function vault(catalog: SelectableDirectoryCatalogV1 = selectable): DirectoryRollbackVaultV1 {
  return {
    acceptCatalog: vi.fn(async () => catalog),
  } as unknown as DirectoryRollbackVaultV1;
}

describe('Nostr directory relay transport', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.verifyRelayCatalogs.mockImplementation(() => mocks.candidate);
    mocks.verifyCentralizedSingleRelayCatalog.mockImplementation(() => mocks.candidate);
  });

  it('requires two complete 16-shard EOSE views and forwards raw EVENT envelopes', async () => {
    const sockets: MockRelay[] = [];
    const result = await refreshNostrDirectoryV1({
      relays: ['wss://relay-a.example', 'wss://relay-b.example'],
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: vault(),
      webSocketFactory: (url) => {
        const socket = new MockRelay(url);
        sockets.push(socket);
        return socket;
      },
    });
    expect(result).toEqual(selectable);
    expect(sockets).toHaveLength(2);
    expect(sockets.every((socket) =>
      socket.sent.filter((message) => JSON.parse(message)[0] === 'REQ').length === 16)).toBe(true);
    const call = mocks.verifyRelayCatalogs.mock.calls[0] as unknown as [Uint8Array];
    const batch = JSON.parse(new TextDecoder().decode(call[0]));
    expect(batch.directoryMode).toBe('strict-multi-relay');
    expect(batch.relays).toHaveLength(2);
    expect(batch.relays[0].eventMessages).toHaveLength(16);
    expect(batch.relays[0].eventMessages[0]).toContain('relay-a.example');
    expect(mocks.candidate.free).toHaveBeenCalledOnce();
  });

  it('accepts exactly one relay only through explicit centralized/degraded mode', async () => {
    const durable = vault(centralizedSelectable);
    const result = await refreshNostrDirectoryV1({
      relays: ['wss://central.example'],
      relayMode: 'centralized-single-relay',
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: durable,
      webSocketFactory: (url) => new MockRelay(url),
    });
    expect(result).toEqual(centralizedSelectable);
    expect(mocks.verifyRelayCatalogs).not.toHaveBeenCalled();
    expect(mocks.verifyCentralizedSingleRelayCatalog).toHaveBeenCalledOnce();
    const call = mocks.verifyCentralizedSingleRelayCatalog.mock.calls[0] as unknown as [Uint8Array];
    const batch = JSON.parse(new TextDecoder().decode(call[0]));
    expect(batch.directoryMode).toBe('centralized-single-relay');
    expect(batch.relays).toHaveLength(1);
  });

  it('rejects one relay without opt-in, zero, more than eight, or centralized mode with two', async () => {
    const common = {
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: vault(),
      webSocketFactory: (url: string) => new MockRelay(url),
    };
    await expect(refreshNostrDirectoryV1({
      ...common,
      relays: ['wss://central.example'],
    })).rejects.toThrow(/strict directory refresh requires two to eight/);
    await expect(refreshNostrDirectoryV1({
      ...common,
      relays: [],
    })).rejects.toThrow(/strict directory refresh requires two to eight/);
    await expect(refreshNostrDirectoryV1({
      ...common,
      relays: Array.from({ length: 9 }, (_, index) => `wss://relay-${index}.example`),
    })).rejects.toThrow(/strict directory refresh requires two to eight/);
    await expect(refreshNostrDirectoryV1({
      ...common,
      relays: ['wss://one.example', 'wss://two.example'],
      relayMode: 'centralized-single-relay',
    })).rejects.toThrow(/requires exactly one relay URL/);
    expect(mocks.verifyRelayCatalogs).not.toHaveBeenCalled();
    expect(mocks.verifyCentralizedSingleRelayCatalog).not.toHaveBeenCalled();
  });

  it('does not accept a relay missing one EOSE as a partial catalog', async () => {
    await expect(refreshNostrDirectoryV1({
      relays: ['wss://relay-a.example', 'wss://relay-b.example'],
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: vault(),
      timeoutMs: 10,
      webSocketFactory: (url) => new MockRelay(url, url.includes('relay-b') ? 15 : null),
    })).rejects.toThrow(/fewer than two complete/);
    expect(mocks.verifyRelayCatalogs).not.toHaveBeenCalled();
    expect(mocks.verifyCentralizedSingleRelayCatalog).not.toHaveBeenCalled();
  });

  it('does not retry or upgrade a failed centralized relay into another mode', async () => {
    const factory = vi.fn(() => new MockRelay('central', 15));
    await expect(refreshNostrDirectoryV1({
      relays: ['wss://central.example'],
      relayMode: 'centralized-single-relay',
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: vault(centralizedSelectable),
      timeoutMs: 10,
      webSocketFactory: factory,
    })).rejects.toThrow(/centralized directory relay did not return one complete/);
    expect(factory).toHaveBeenCalledOnce();
    expect(mocks.verifyRelayCatalogs).not.toHaveBeenCalled();
    expect(mocks.verifyCentralizedSingleRelayCatalog).not.toHaveBeenCalled();
  });

  it('propagates Rust same-epoch split-view rejection before durable acceptance', async () => {
    mocks.verifyRelayCatalogs.mockImplementation(() => {
      throw new Error('directory split view at shard 2 epoch 9');
    });
    const durable = vault();
    await expect(refreshNostrDirectoryV1({
      relays: ['wss://relay-a.example', 'wss://relay-b.example'],
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: durable,
      webSocketFactory: (url) => new MockRelay(url),
    })).rejects.toThrow(/split view/);
    expect(durable.acceptCatalog).not.toHaveBeenCalled();
  });

  it('closes a relay immediately at its byte budget while two bounded relays can proceed', async () => {
    const sockets: MockRelay[] = [];
    await expect(refreshNostrDirectoryV1({
      relays: [
        'wss://relay-flood.example',
        'wss://relay-a.example',
        'wss://relay-b.example',
      ],
      pinnedDirectoryPubkeyHex: directoryPubkey,
      vault: vault(),
      webSocketFactory: (url) => {
        const socket = new MockRelay(url, null, url.includes('flood'));
        sockets.push(socket);
        return socket;
      },
    })).resolves.toEqual(selectable);
    expect(sockets[0].closeCalls).toBeGreaterThan(0);
    const call = mocks.verifyRelayCatalogs.mock.calls[0] as unknown as [Uint8Array];
    const batch = JSON.parse(new TextDecoder().decode(call[0]));
    expect(batch.relays).toHaveLength(2);
    expect(batch.relays.every((relay: any) => !relay.eventMessages[0].includes('xxx'))).toBe(true);
    expect(mocks.verifyCentralizedSingleRelayCatalog).not.toHaveBeenCalled();
  });
});
