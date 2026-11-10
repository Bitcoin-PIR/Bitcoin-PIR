/**
 * The /directory page: the service directory as a wallet reads it, verified
 * against the pinned directory key (`refreshNostrDirectoryV1`), with relay,
 * shard and raw-event inspection. Listing is not trust: a wallet still
 * checks each provider live before it uses it.
 */

import { describeDirectoryCatalogV1 } from './directory-providers.js';
import { directoryTime, renderDirectoryCatalog } from './directory-view.js';
import { refreshNostrDirectoryV1 } from './nostr-directory.js';
import { PRODUCTION_DIRECTORY } from './production-providers.js';
import { initSdkWasm } from './sdk-bridge.js';

const status = document.getElementById('status')!;
const content = document.getElementById('catalog')!;
const refresh = document.getElementById('refresh') as HTMLButtonElement;

async function load(): Promise<void> {
  refresh.disabled = true;
  content.replaceChildren();
  content.setAttribute('aria-busy', 'true');
  status.textContent = 'Reading the service directory…';
  try {
    if (!await initSdkWasm()) throw new Error('the PIR SDK failed to load');
    const catalog = await refreshNostrDirectoryV1(PRODUCTION_DIRECTORY, { inspect: true });
    renderDirectoryCatalog(content, catalog);
    status.textContent = `${describeDirectoryCatalogV1(catalog)} · Read at ${directoryTime(Math.floor(Date.now() / 1000))}`;
  } catch (error) {
    content.replaceChildren();
    status.textContent = `Unavailable: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    content.setAttribute('aria-busy', 'false');
    refresh.disabled = false;
  }
}

refresh.addEventListener('click', () => void load());
void load();
