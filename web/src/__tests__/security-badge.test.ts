import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { renderSecurityBadgeTextRowsV1 } from '../security-badge.js';

class FakeDocument {
  createElement(tagName: string): FakeElement {
    return new FakeElement(this, tagName);
  }
}

class FakeElement {
  readonly children: FakeElement[] = [];
  className = '';
  textContent: string | null = '';
  title = '';

  constructor(
    readonly ownerDocument: FakeDocument,
    readonly tagName: string,
  ) {}

  append(...nodes: FakeElement[]): void {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }
}

function allTags(root: FakeElement): string[] {
  return [root.tagName, ...root.children.flatMap(allTags)];
}

describe('pre-verification security badge rendering', () => {
  it('keeps server-controlled attestation strings as inert text and tooltips', () => {
    const document = new FakeDocument();
    const root = document.createElement('div');
    const payload = '\"><img src=x onerror="globalThis.pwned=1">';

    renderSecurityBadgeTextRowsV1(
      root as unknown as HTMLElement,
      payload,
      [{ label: 'git rev', value: payload, title: payload }],
    );

    expect(root.children[0]?.textContent).toBe(payload);
    expect(root.children[1]?.children[1]?.textContent).toBe(payload);
    expect(root.children[1]?.children[1]?.title).toBe(payload);
    expect(allTags(root)).toEqual(['div', 'span', 'div', 'span', 'span']);
  });

  it('keeps both inline security callbacks on the text-only renderer', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const attestStart = html.indexOf('function renderAttestBadge');
    const operatorStart = html.indexOf('function renderOperatorBadge');
    const escapeStart = html.indexOf('function escapeHtml');
    expect(attestStart).toBeGreaterThan(0);
    expect(operatorStart).toBeGreaterThan(attestStart);
    expect(escapeStart).toBeGreaterThan(operatorStart);

    const attest = html.slice(attestStart, operatorStart);
    const operator = html.slice(operatorStart, escapeStart);
    for (const callback of [attest, operator]) {
      expect(callback).toContain('renderSecurityBadgeTextRowsV1');
      expect(callback).not.toMatch(/\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML/);
    }
  });

  it('keeps live provider catalog and proof strings out of raw HTML interpolation', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');

    expect(html).not.toContain('planText.innerHTML');
    expect(html).toContain('renderSyncPlanTextV1(');
    expect(html).toContain('${escapeHtml(stepLabel)}</code>');
    expect(html).not.toContain('${stepLabel}</code>');
    expect(html).toContain('${escapeHtml(o.text)}</span>');
    for (const unsafe of [
      'title="${proof.muhashHex}"',
      'title="${proof.bucketSuperRootHex}"',
      'title="${proof.onionSuperRootHex}"',
      'title="${proof.builderBinarySha256Hex}"',
      'title="${anchor.blockHashHex}"',
      'title="${anchor.muhashHex}"',
      'title="${bhtm.treeRootHex}"',
      'title="${bhtm.streamingUkiMeasurementHex}"',
      'title="${source.index.sha256}',
      'title="${oram.commit}"',
    ]) {
      expect(html).not.toContain(unsafe);
    }
    expect(html).toContain('qiData = prepare(candidate);');
    expect(html).toContain('__bitcoinPirPrepareQueryInspectorRenderDataV1');
    expect(html).not.toContain('qiData = hpInspectorDataMap?.get(qi);');
  });

  it('pins every inline script and rejects inline event handlers with CSP', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const policy = html.match(
      /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/,
    )?.[1];
    expect(policy).toBeDefined();
    const scriptPolicy = policy?.split(';').map((part) => part.trim())
      .find((part) => part.startsWith('script-src '));
    expect(scriptPolicy).toBeDefined();
    expect(scriptPolicy).not.toContain("'unsafe-inline'");
    expect(scriptPolicy).not.toContain("'unsafe-eval'");
    expect(scriptPolicy).toContain("'wasm-unsafe-eval'");
    const markupWithoutExecutableBlocks = html
      .replace(/<script(?:\s[^>]*)?>[\s\S]*?<\/script>/gi, '')
      .replace(/<style(?:\s[^>]*)?>[\s\S]*?<\/style>/gi, '');
    expect(markupWithoutExecutableBlocks).not.toMatch(/\son[a-z0-9_-]+\s*=/i);

    const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)];
    expect(inlineScripts).toHaveLength(3);
    for (const match of inlineScripts) {
      const digest = createHash('sha256').update(match[1]).digest('base64');
      expect(scriptPolicy).toContain(`'sha256-${digest}'`);
    }
  });

  it('ships an OnionPIR loader that does not require unsafe-eval', () => {
    const loader = readFileSync(
      new URL('../../public/wasm/onionpir_client.mjs', import.meta.url),
      'utf8',
    );
    expect(loader).not.toMatch(/\bnew\s+Function\b|\beval\s*\(/);
  });

  it('covers every production HTML page and excludes the dev-only issuer demo', () => {
    const reproduce = readFileSync(new URL('../../reproduce.html', import.meta.url), 'utf8');
    const policy = reproduce.match(
      /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/,
    )?.[1];
    expect(policy).toBeDefined();
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("base-uri 'none'");
    expect(policy).toContain("form-action 'none'");
    expect(policy).not.toContain("'unsafe-eval'");
    expect(reproduce).not.toMatch(/\son[a-z0-9_-]+\s*=/i);

    const inlineScripts = [
      ...reproduce.matchAll(new RegExp('<script>([\\s\\S]*?)</script>', 'g')),
    ];
    expect(inlineScripts).toHaveLength(1);
    const digest = createHash('sha256').update(inlineScripts[0][1]).digest('base64');
    expect(policy).toContain("'sha256-" + digest + "'");

    const main = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    for (const html of [main, reproduce]) {
      expect(html).not.toContain('fonts.googleapis.com');
      expect(html).not.toContain('fonts.gstatic.com');
    }
    const viteConfig = readFileSync(new URL('../../vite.config.js', import.meta.url), 'utf8');
    expect(viteConfig).not.toContain("'ratelimit-demo':");
    expect(viteConfig).toContain('strip-production-loopback-csp');
  });
});
