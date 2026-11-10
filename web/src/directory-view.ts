/** Read-only directory inspector. Raw relay claims are never rendered as verified results. */
import { directoryProvidersV1 } from './directory-providers.js';
import type { DirectoryInspectionV1, NostrDirectoryCatalogV1 } from './nostr-directory.js';

export function directoryTime(unix: number): string {
  return unix > 0 ? new Date(unix * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : '—';
}

/** A label for an untrusted EVENT frame, not a signature or membership verdict. */
export function directoryEventLabel(message: string): string {
  const frame: unknown = JSON.parse(message);
  const event = Array.isArray(frame) ? frame[2] : null;
  if (!event || typeof event !== 'object') return 'Malformed event';
  const tags: unknown = event.tags;
  const coordinate: unknown = Array.isArray(tags)
    ? tags.find((tag: unknown) => Array.isArray(tag) && tag[0] === 'd')?.[1] : null;
  let content: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = typeof event.content === 'string' ? JSON.parse(event.content) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) content = parsed as Record<string, unknown>;
  } catch { /* A rejected event may have malformed content. */ }
  const kind = typeof coordinate === 'string' && coordinate.startsWith('bitcoinpir-service-directory-checkpoint-v1:')
    ? 'Checkpoint' : typeof coordinate === 'string' && coordinate.startsWith('bitcoinpir-service-directory-v1:')
      ? content?.status === 'tombstone' ? 'Tombstone' : 'Entry' : 'Event';
  const revision = kind === 'Checkpoint' ? content?.checkpoint_epoch : content?.directory_sequence;
  const label = typeof revision === 'number' ? ` · ${kind === 'Checkpoint' ? 'epoch' : 'sequence'} ${revision}` : '';
  return `${kind}${label} · ${typeof event.id === 'string' ? event.id : 'no event id'}`;
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K, text?: string, className?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function section(title: string): HTMLElement {
  const node = element('section');
  node.append(element('h2', title));
  return node;
}

function table(parent: HTMLElement, headings: string[]): HTMLTableSectionElement {
  const wrap = element('div', undefined, 'table-wrap');
  const grid = element('table');
  const head = element('thead');
  const row = element('tr');
  for (const text of headings) {
    const th = element('th', text);
    th.scope = 'col';
    row.append(th);
  }
  head.append(row);
  const body = element('tbody');
  grid.append(head, body);
  wrap.append(grid);
  parent.append(wrap);
  return body;
}

function field(list: HTMLDListElement, label: string, value: string): void {
  list.append(element('dt', label), element('dd', value, 'mono'));
}

function rawEvent(message: string): HTMLDetailsElement {
  const details = element('details', undefined, 'event');
  details.append(element('summary', directoryEventLabel(message), 'mono'));
  // Keep the exact frame (including duplicate fields) visible, not a JSON round trip.
  details.addEventListener('toggle', () => {
    if (!details.open || details.childElementCount > 1) return;
    details.append(element('pre', message));
    const frame: unknown = JSON.parse(message);
    const content = Array.isArray(frame) ? frame[2]?.content : null;
    if (typeof content === 'string') {
      let text = content;
      try { text = JSON.stringify(JSON.parse(content), null, 2); } catch { /* Raw content. */ }
      details.append(element('h3', 'Decoded content (relay claim)'), element('pre', text));
    }
  });
  return details;
}

function relaySection(inspection: DirectoryInspectionV1): HTMLElement {
  const node = section('Relays');
  const body = table(node, ['Relay', 'Transport read', 'EVENT frames']);
  for (const relay of inspection.relays) {
    const row = element('tr');
    row.append(
      element('td', relay.url, 'mono'),
      element('td', relay.error ?? 'EOSE on all 16 shards', relay.error ? 'failure wrap' : ''),
      element('td', relay.messages === null ? '—' : String(relay.messages.length), 'mono'),
    );
    body.append(row);
  }
  return node;
}

function providerSection(catalog: NostrDirectoryCatalogV1): HTMLElement {
  const node = section('Nodes');
  const providers = directoryProvidersV1(catalog);
  if (providers.length === 0) {
    node.append(element('p', 'No active nodes with backend hints in the accepted catalog.'));
    return node;
  }
  const entries = new Map(catalog.inspection?.entries.map((entry) => [entry.providerId, entry]));
  const body = table(node, ['Server', 'Role', 'Listed trust', 'Backends · access', 'Endpoints', 'Listed health', 'Sequence', 'Valid until']);
  for (const provider of providers) {
    const entry = entries.get(provider.providerIdHex);
    const row = element('tr');
    const identity = element('details');
    identity.append(element('summary', provider.serverId, 'mono'));
    const fields = element('dl');
    field(fields, 'Provider ID', provider.providerIdHex);
    field(fields, 'Operator key', provider.operatorPubkeyHex);
    if (entry) field(fields, 'Verified entry event ID', entry.eventId);
    identity.append(fields);
    const server = element('td');
    server.append(identity);
    const endpoints = element('td', undefined, 'mono');
    for (const endpoint of provider.endpoints) endpoints.append(element('div', endpoint));
    row.append(
      server,
      element('td', provider.role),
      element('td', provider.trustTier === 'sev-snp' ? 'SEV-SNP' : 'operator identity'),
      element('td', Object.entries(provider.backends).map(([backend, access]) => `${backend} · ${access}`).join(', ')),
      endpoints,
      element('td', provider.health, `health ${provider.health}`),
      element('td', entry ? String(entry.directorySequence) : '—', 'mono'),
      element('td', directoryTime(provider.validUntil), 'mono'),
    );
    body.append(row);
  }
  return node;
}

function shardSection(catalog: NostrDirectoryCatalogV1, inspection: DirectoryInspectionV1): HTMLElement {
  const node = section(`Shards · ${inspection.shards.length}/16 accepted`);
  const grid = element('div', undefined, 'shards');
  for (let index = 0; index < 16; index += 1) {
    const shard = inspection.shards.find((item) => item.shard === index);
    const details = element('details', undefined, `shard ${shard ? 'accepted' : 'missing'}`);
    details.append(element('summary', `${index.toString(16)} · ${shard ? `epoch ${shard.epoch}` : 'not accepted'}`));
    if (shard) {
      const fields = element('dl');
      field(fields, 'Agreeing relay views', String(shard.views));
      field(fields, 'Verified checkpoint event ID', shard.eventId);
      field(fields, 'Active entries', String(inspection.entries.filter((entry) => entry.providerId.startsWith(index.toString(16))).length));
      details.append(fields);
    }
    for (const rejection of catalog.rejected.filter((item) => item.shard === index || item.shard === null)) {
      details.append(element('p', `${rejection.relay ?? 'Catalog'}: ${rejection.reason}`, 'failure wrap'));
    }
    grid.append(details);
  }
  node.append(grid);
  return node;
}

export function renderDirectoryCatalog(root: HTMLElement, catalog: NostrDirectoryCatalogV1): void {
  root.replaceChildren();
  const inspection = catalog.inspection;
  if (inspection) root.append(relaySection(inspection));
  root.append(providerSection(catalog));
  if (inspection) root.append(shardSection(catalog, inspection));
  if (catalog.rejected.length > 0) {
    const node = section(`Rejected views · ${catalog.rejected.length}`);
    const body = table(node, ['Relay', 'Shard', 'Reason']);
    for (const rejection of catalog.rejected) {
      const row = element('tr');
      row.append(
        element('td', rejection.relay ?? 'Catalog', 'mono'),
        element('td', rejection.shard === null ? 'all' : rejection.shard.toString(16), 'mono'),
        element('td', rejection.reason, 'failure wrap'),
      );
      body.append(row);
    }
    root.append(node);
  }
  if (inspection) {
    const events = element('details', undefined, 'events');
    events.append(element('summary', 'Raw relay events'));
    events.append(element('p', 'Received EVENT frames, not individual verification verdicts. Accepted checkpoint and entry IDs are shown above; rejection reasons apply to relay views of shards.'));
    for (const relay of inspection.relays) {
      events.append(element('h3', relay.url, 'mono'));
      if (!relay.messages?.length) {
        events.append(element('p', relay.error ? 'Incomplete read discarded.' : 'No EVENT frames received.'));
      } else {
        for (const message of relay.messages) events.append(rawEvent(message));
      }
    }
    root.append(events);
  }
}
