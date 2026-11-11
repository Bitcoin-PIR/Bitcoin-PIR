import { afterEach, describe, expect, it, vi } from 'vitest';
import { directoryEventLabel, directoryTime, renderDirectoryCatalog } from '../directory-view.js';
import type { NostrDirectoryCatalogV1 } from '../nostr-directory.js';

// Minimal recording DOM, following security-badge.test.ts; no browser or network.
class FakeElement {
  children: FakeElement[] = [];
  textContent = '';
  className = '';
  open = false;
  listeners = new Map<string, () => void>();
  constructor(readonly tagName: string) {}
  get childElementCount(): number { return this.children.length; }
  append(...nodes: FakeElement[]): void { this.children.push(...nodes); }
  replaceChildren(...nodes: FakeElement[]): void { this.children = nodes; }
  addEventListener(name: string, listener: () => void): void { this.listeners.set(name, listener); }
}

const all = (node: FakeElement): FakeElement[] => [node, ...node.children.flatMap(all)];
const text = (node: FakeElement): string => all(node).map((item) => item.textContent).join('\n');
const frame = (value: unknown) => JSON.stringify(['EVENT', 'bitcoinpir-directory-v1-shard-0', value]);

function catalog(): NostrDirectoryCatalogV1 {
  return {
    mode: 'centralized-single-relay', degraded: true, validUntil: 1_800_000_000,
    candidates: { dpf: [], harmony: [], onion: [], oram: [] }, rejected: [],
    inspection: {
      shards: [{ shard: 0, epoch: 12, views: 1, eventId: 'verified-checkpoint' }],
      entries: [],
      relays: [{ url: 'wss://relay.example', messages: [], error: null }],
    },
  };
}

function render(value: NostrDirectoryCatalogV1): FakeElement {
  vi.stubGlobal('document', { createElement: (tag: string) => new FakeElement(tag) });
  const root = new FakeElement('div');
  renderDirectoryCatalog(root as unknown as HTMLElement, value);
  return root;
}

afterEach(() => vi.unstubAllGlobals());

describe('directory inspector', () => {
  it('shows sixteen shard disclosures, accepted epochs and an explicit empty node state', () => {
    const root = render(catalog());
    expect(all(root).filter((item) => item.className.startsWith('shard '))).toHaveLength(16);
    expect(text(root)).toContain('0 · epoch 12');
    expect(text(root)).toContain('f · not accepted');
    expect(text(root)).toContain('verified-checkpoint');
    expect(text(root)).toContain('No active nodes with backend hints');
    expect(text(root)).toContain('No EVENT frames received.');
    expect(text(root)).toContain('not individual verification verdicts');
  });

  it('renders failed reads and shard rejections, without fabricating event counts or accepted IDs', () => {
    const value = catalog();
    value.inspection!.shards = [];
    value.inspection!.relays[0] = { url: 'wss://relay.example', messages: null, error: 'timeout before EOSE' };
    value.rejected = [{ relay: 'wss://relay.example', shard: null, reason: 'timeout before EOSE' },
      { relay: null, shard: 0, reason: 'no relay returned a valid view' }];
    const root = render(value);
    expect(text(root)).toContain('Shards · 0/16 accepted');
    expect(text(root)).toContain('Rejected views · 2');
    expect(text(root)).toContain('timeout before EOSE');
    expect(text(root)).toContain('Incomplete read discarded.');
    expect(text(root)).not.toContain('EOSE on all 16 shards');
    expect(text(root)).not.toContain('verified-checkpoint');
  });

  it('shows each node once, all endpoints, full UTC expiry, sequence and verified identity details', () => {
    const value = catalog();
    const provider = {
      providerIdHex: '0'.repeat(64), serverId: 'test-node', operatorPubkeyHex: '1'.repeat(64),
      endpoints: ['wss://one.example', 'wss://two.example'], role: 'primary' as const,
      trustTier: 'operator-identity' as const, backends: { dpf: 'free' as const, harmony: 'paid' as const },
      health: 'available' as const, validUntil: 1_800_000_000,
    };
    value.candidates.dpf.push({ provider, access: 'free' });
    value.candidates.harmony.push({ provider, access: 'paid' });
    value.inspection!.entries.push({ providerId: provider.providerIdHex, eventId: 'verified-entry', directorySequence: 11 });
    const root = render(value);
    expect(all(root).filter((node) => node.textContent === 'test-node')).toHaveLength(1);
    for (const expected of ['wss://one.example', 'wss://two.example', '11', 'verified-entry', provider.operatorPubkeyHex,
      '2027-01-15 08:00:00 UTC', 'Listed health', 'Listed trust']) expect(text(root)).toContain(expected);
  });

  it('keeps hostile and malformed raw events as inert text, formatted only on expansion', () => {
    const payload = '<img src=x onerror="globalThis.pwned=1">';
    const value = catalog();
    value.inspection!.relays[0].messages = [frame({ id: payload, tags: null, content: JSON.stringify({ payload }) }), frame(null)];
    const root = render(value);
    expect(all(root).some((node) => node.tagName === 'pre')).toBe(false);
    expect(text(root)).toContain(`Event · ${payload}`);
    expect(text(root)).toContain('Malformed event');
    const event = all(root).find((node) => node.className === 'event')!;
    event.open = true;
    event.listeners.get('toggle')!();
    event.listeners.get('toggle')!();
    expect(all(event).filter((node) => node.tagName === 'pre')).toHaveLength(2);
    expect(text(event)).toContain('Decoded content (relay claim)');
    expect(text(event)).toContain(payload);
    expect(all(root).some((node) => ['img', 'script'].includes(node.tagName))).toBe(false);
  });

  it('preserves exact raw frames, including duplicate JSON fields rejected by the verifier', () => {
    const value = catalog();
    const message = '["EVENT","bitcoinpir-directory-v1-shard-0",{ "id":"original", "id":"duplicate", "content":"{}" }]';
    value.inspection!.relays[0].messages = [message];
    const root = render(value);
    const event = all(root).find((node) => node.className === 'event')!;
    event.open = true;
    event.listeners.get('toggle')!();
    expect(event.children[1].tagName).toBe('pre');
    expect(event.children[1].textContent).toBe(message);
  });

  it('labels raw coordinates without calling their claims verified and formats UTC timestamps', () => {
    expect(directoryEventLabel(frame({ id: 'c', tags: [['d', 'bitcoinpir-service-directory-checkpoint-v1:a']] })))
      .toBe('Checkpoint · c');
    expect(directoryEventLabel(frame({ id: 'e', tags: [['d', 'bitcoinpir-service-directory-v1:123']] })))
      .toBe('Entry · e');
    expect(directoryEventLabel(frame({ id: 't', tags: [['d', 'bitcoinpir-service-directory-v1:123']],
      content: JSON.stringify({ status: 'tombstone', directory_sequence: 13 }) })))
      .toBe('Tombstone · sequence 13 · t');
    expect(directoryEventLabel(frame({ id: 'c', tags: [['d', 'bitcoinpir-service-directory-checkpoint-v1:a']],
      content: JSON.stringify({ checkpoint_epoch: 12 }) })))
      .toBe('Checkpoint · epoch 12 · c');
    expect(directoryEventLabel(frame({ id: 'broken', tags: [], content: 'not JSON' }))).toBe('Event · broken');
    expect(directoryEventLabel(frame({ tags: [null, 3] }))).toBe('Event · no event id');
    expect(directoryTime(0)).toBe('—');
    expect(directoryTime(1_800_000_000)).toBe('2027-01-15 08:00:00 UTC');
  });
});
