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
});
