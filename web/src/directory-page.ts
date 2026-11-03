/**
 * The /directory page: the service directory as a wallet reads it, verified
 * against the pinned directory key (`refreshNostrDirectoryV1`), one row per
 * provider with the services it offers. Listing is not trust: a wallet still
 * checks each provider live before it uses it.
 */

import { describeDirectoryCatalogV1, directoryProvidersV1 } from './directory-providers.js';
import { refreshNostrDirectoryV1, type DirectoryProviderV1 } from './nostr-directory.js';
import { PRODUCTION_DIRECTORY } from './production-providers.js';
import { initSdkWasm } from './sdk-bridge.js';

const status = document.getElementById('status')!;
const rows = document.getElementById('rows')!;
const refresh = document.getElementById('refresh') as HTMLButtonElement;

function cell(text: string, className?: string): HTMLTableCellElement {
  const td = document.createElement('td');
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function row(provider: DirectoryProviderV1): HTMLTableRowElement {
  const tr = document.createElement('tr');
  const backends = Object.entries(provider.backends)
    .map(([backend, access]) => `${backend} · ${access}`)
    .join(', ');
  const until = new Date(provider.validUntil * 1000).toISOString().slice(0, 10);
  tr.append(
    cell(provider.serverId, 'mono'),
    cell(provider.role),
    cell(provider.trustTier === 'sev-snp' ? 'SEV-SNP' : 'operator identity'),
    cell(backends),
    cell(provider.endpoints[0] ?? '', 'mono'),
    cell(provider.health, `health ${provider.health}`),
    cell(until, 'mono'),
  );
  return tr;
}

async function load(): Promise<void> {
  refresh.disabled = true;
  status.textContent = 'Reading the service directory…';
  try {
    if (!await initSdkWasm()) throw new Error('the PIR SDK failed to load');
    const catalog = await refreshNostrDirectoryV1(PRODUCTION_DIRECTORY);
    const providers = directoryProvidersV1(catalog);
    rows.replaceChildren(...providers.map(row));
    status.textContent = describeDirectoryCatalogV1(catalog);
  } catch (error) {
    rows.replaceChildren();
    status.textContent = `Unavailable: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    refresh.disabled = false;
  }
}

refresh.addEventListener('click', () => void load());
void load();
