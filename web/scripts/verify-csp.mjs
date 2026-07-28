import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';

const distUrl = new URL('../dist-web/', import.meta.url);
const onionModuleUrl = new URL(
  '../dist-web/wasm/onionpir_client.mjs',
  import.meta.url,
);
const onionLoader = readFileSync(onionModuleUrl, 'utf8');
const htmlFiles = readdirSync(distUrl)
  .filter((name) => name.endsWith('.html'))
  .sort();
if (htmlFiles.includes('ratelimit-demo.html')) {
  throw new Error('development-only rate-limit demo was included in production');
}
const expectedInlineCounts = new Map([
  ['index.html', 2],
  ['reproduce.html', 1],
]);
if (htmlFiles.join(',') !== [...expectedInlineCounts.keys()].sort().join(',')) {
  throw new Error(`unexpected production HTML set: ${htmlFiles.join(',')}`);
}

let totalInlineCount = 0;
for (const name of htmlFiles) {
  const html = readFileSync(new URL(name, distUrl), 'utf8');
  const policy = html.match(
    /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/,
  )?.[1];
  if (!policy) throw new Error(`${name} has no Content-Security-Policy meta tag`);
  if (policy.includes('http://') || policy.includes('ws://')) {
    throw new Error(`${name} production CSP permits an insecure loopback transport`);
  }

  const directives = new Map(policy.split(';').map((part) => {
    const fields = part.trim().split(/\s+/);
    return [fields[0], fields.slice(1)];
  }));
  const scriptSources = directives.get('script-src');
  if (!scriptSources
      || scriptSources.includes("'unsafe-inline'")
      || scriptSources.includes("'unsafe-eval'")
      || !scriptSources.includes("'self'")
      || (name === 'index.html' && !scriptSources.includes("'wasm-unsafe-eval'"))) {
    throw new Error(`${name} script-src is missing its strict sources`);
  }
  for (const [directive, required] of [
    ['default-src', "'none'"],
    ['base-uri', "'none'"],
    ['object-src', "'none'"],
    ['frame-src', "'none'"],
    ['form-action', "'none'"],
  ]) {
    if (!directives.get(directive)?.includes(required)) {
      throw new Error(`${name} CSP is missing ${directive} ${required}`);
    }
  }
  if (directives.get('font-src')?.some((source) => source.startsWith('http'))
      || html.includes('fonts.googleapis.com')
      || html.includes('fonts.gstatic.com')) {
    throw new Error(`${name} loads a third-party font resource`);
  }
  if (/\son[a-z0-9_-]+\s*=/i.test(html)) {
    throw new Error(`${name} contains an inline event-handler attribute`);
  }

  let inlineCount = 0;
  for (const match of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (/\ssrc\s*=/.test(match[1])) continue;
    inlineCount += 1;
    const digest = createHash('sha256').update(match[2]).digest('base64');
    if (!scriptSources.includes(`'sha256-${digest}'`)) {
      throw new Error(`${name} inline script ${inlineCount} is not hash-pinned`);
    }
  }
  if (inlineCount !== expectedInlineCounts.get(name)) {
    throw new Error(`${name} has an unexpected inline-script count: ${inlineCount}`);
  }
  totalInlineCount += inlineCount;
}

if (/\bnew\s+Function\b|\beval\s*\(/.test(onionLoader)) {
  throw new Error('production OnionPIR loader requires CSP-forbidden dynamic execution');
}
const onionFactory = (await import(onionModuleUrl.href)).default;
if (typeof onionFactory !== 'function') {
  throw new Error('production OnionPIR loader has no default module factory');
}
const onionModule = await onionFactory({
  print() {},
  printErr() {},
});
const onionParams = onionModule.paramsInfo?.();
if (!onionParams || onionParams.polyDegree <= 0 || onionParams.numEntries <= 0) {
  throw new Error('production OnionPIR loader did not initialize its embind API');
}

process.stdout.write(
  `verified ${htmlFiles.length} production pages with ${totalInlineCount} pinned inline scripts and CSP-safe OnionPIR initialization\n`,
);
