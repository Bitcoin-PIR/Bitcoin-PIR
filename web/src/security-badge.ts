/**
 * Text-only rendering for values received before strict server verification.
 *
 * Attestation and operator-identity callbacks can contain server-controlled
 * strings.  Rendering them as HTML would let an untrusted endpoint execute in
 * the application origin and reach the capability vault.  This helper owns no
 * HTML parser entry point: every value is assigned through `textContent`, and
 * every tooltip through the DOM `title` property.
 */

export interface SecurityBadgeTextRowV1 {
  label: string;
  value: string;
  title?: string;
}

export function renderSecurityBadgeTextRowsV1(
  element: HTMLElement,
  stateText: string,
  rows: readonly SecurityBadgeTextRowV1[],
): void {
  const document = element.ownerDocument;
  const state = document.createElement('span');
  state.className = 'ab-state';
  state.textContent = stateText;

  const children: HTMLElement[] = [state];
  for (const row of rows) {
    const container = document.createElement('div');
    container.className = 'ab-row';

    const label = document.createElement('span');
    label.className = 'ab-label';
    label.textContent = row.label;

    const value = document.createElement('span');
    value.className = 'ab-val';
    value.textContent = row.value;
    if (row.title !== undefined) value.title = row.title;

    container.append(label, value);
    children.push(container);
  }
  element.replaceChildren(...children);
}
