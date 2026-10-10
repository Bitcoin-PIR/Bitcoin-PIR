import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';

// Every inline script must be hash-pinned in its page's CSP (or the browser
// refuses to run it), and the production CSP must not allow the loopback
// transports the dev server uses.
const distUrl = new URL('../dist-web/', import.meta.url);
const htmlFiles = readdirSync(distUrl).filter((name) => name.endsWith('.html'));

for (const name of htmlFiles) {
  const html = readFileSync(new URL(name, distUrl), 'utf8');
  const policy = html.match(
    /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/,
  )?.[1];
  if (!policy) throw new Error(`${name} has no Content-Security-Policy meta tag`);
  if (policy.includes('http://') || policy.includes('ws://')) {
    throw new Error(`${name} production CSP permits an insecure loopback transport`);
  }
  for (const match of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (/\ssrc\s*=/.test(match[1])) continue;
    const digest = createHash('sha256').update(match[2]).digest('base64');
    if (!policy.includes(`'sha256-${digest}'`)) {
      throw new Error(`${name} has an inline script that is not hash-pinned`);
    }
  }
}

process.stdout.write(`verified the CSP of ${htmlFiles.length} production pages\n`);
