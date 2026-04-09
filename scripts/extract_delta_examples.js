#!/usr/bin/env node
/**
 * Extract "example SPKs with visible activity in a delta" and update
 * web/src/example_spks.json with a per-delta list.
 *
 * Usage:
 *   node scripts/extract_delta_examples.js <start_height> <end_height>
 *   node scripts/extract_delta_examples.js 940611 944000
 *
 * What it does:
 *   1. Loads the existing web/src/example_spks.json. Handles both the
 *      legacy flat-array shape and the new per-DB object shape.
 *   2. Computes hash160 = ripemd160(sha256(spk_bytes)) for each entry in
 *      the "main" list (the 1000 example scriptPubKeys).
 *   3. Streams /Volumes/Bitcoin/data/intermediate/delta_grouped_<A>_<B>.bin
 *      (the source-of-truth grouped delta from delta_gen_0). For each
 *      target scripthash present in the file, decodes its `num_spent` and
 *      `num_new` counts.
 *   4. Keeps every address with ANY activity (spent > 0 OR new > 0). Both
 *      signals make good demos: the web frontend's delta-activity renderer
 *      shows spent UTXOs with their pre-delta amounts from the prior
 *      snapshot, so "address X had 1,600 sats at height A and the delta
 *      at height B spent them" is a clearer demo than "address X now has
 *      more UTXOs". Reports a breakdown by category (spent-only, new-only,
 *      both) so callers can see the distribution.
 *   5. Writes the list back to web/src/example_spks.json under the key
 *      `delta_<A>_<B>`.
 *
 * Re-run this whenever a new delta database is built.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Args ────────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
if (argv.length !== 2) {
  console.error('Usage: node scripts/extract_delta_examples.js <start_height> <end_height>');
  process.exit(1);
}
const [startStr, endStr] = argv;
const startH = parseInt(startStr, 10);
const endH = parseInt(endStr, 10);
if (!Number.isFinite(startH) || !Number.isFinite(endH) || startH >= endH) {
  console.error(`Invalid height range: ${startStr}..${endStr}`);
  process.exit(1);
}

const deltaKey = `delta_${startH}_${endH}`;
const deltaGroupedPath = `/Volumes/Bitcoin/data/intermediate/delta_grouped_${startH}_${endH}.bin`;
const examplesPath = path.join(__dirname, '..', 'web', 'src', 'example_spks.json');

// ─── Hash160 (must match web/src/hash.ts::scriptHash) ────────────────────────
function hash160(hex) {
  const buf = Buffer.from(hex, 'hex');
  const sha = crypto.createHash('sha256').update(buf).digest();
  return crypto.createHash('ripemd160').update(sha).digest().toString('hex');
}

// ─── Load existing example_spks.json (handle both old flat + new dict) ──────
const raw = JSON.parse(fs.readFileSync(examplesPath, 'utf8'));
let examples;
if (Array.isArray(raw)) {
  // Legacy format: flat array → wrap under "main".
  examples = { main: raw };
  console.log(`[info] Migrating example_spks.json from flat-array to per-DB format.`);
} else if (raw && typeof raw === 'object' && Array.isArray(raw.main)) {
  examples = raw;
} else {
  console.error('example_spks.json has unexpected structure; expected array or {main: [...]}');
  process.exit(1);
}
console.log(`[info] Loaded ${examples.main.length} main example SPKs`);

// ─── Read grouped delta file (source of truth from delta_gen_0) ────────────
if (!fs.existsSync(deltaGroupedPath)) {
  console.error(`[error] Grouped delta not found: ${deltaGroupedPath}`);
  console.error('        Run scripts/build_delta.sh for this height range first.');
  process.exit(1);
}
const gBuf = fs.readFileSync(deltaGroupedPath);
console.log(`[info] Grouped delta: ${gBuf.length.toLocaleString()} bytes`);

// ─── Build set of target scripthashes from the example SPKs ────────────────
const spkByHash = new Map();
for (const spk of examples.main) {
  spkByHash.set(hash160(spk), spk);
}

// ─── Walk the grouped delta and decode each target's spent/new counts ──────
//
// Format (from delta_gen_0_compute_delta.rs):
//   [u32 num_scripts LE]
//   per script:
//     [20B scripthash]
//     [varint num_spent]
//       per spent: [32B txid][varint vout]
//     [varint num_new]
//       per new:   [32B txid][varint vout][varint amount]
function readVarint(off) {
  let r = 0n, shift = 0n, bytes = 0;
  while (true) {
    const b = gBuf[off + bytes];
    bytes++;
    r |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7n;
    if (shift >= 64n) throw new Error('varint too large');
  }
  return [r, bytes];
}

let pos = 0;
const numScripts = gBuf.readUInt32LE(pos);
pos += 4;
console.log(`[info] num_scripts in grouped delta: ${numScripts.toLocaleString()}`);

// matches[hash] = { numSpent, numNew, totalNewAmount }
const matches = new Map();
let scanned = 0;
while (pos < gBuf.length) {
  const sh = gBuf.slice(pos, pos + 20).toString('hex');
  pos += 20;
  let [numSpent, c] = readVarint(pos); pos += c;
  for (let i = 0; i < Number(numSpent); i++) {
    pos += 32; // txid
    const [, c2] = readVarint(pos); pos += c2; // vout
  }
  let [numNew, c3] = readVarint(pos); pos += c3;
  let totalNewAmount = 0n;
  for (let i = 0; i < Number(numNew); i++) {
    pos += 32; // txid
    const [, c4] = readVarint(pos); pos += c4; // vout
    const [amt, c5] = readVarint(pos); pos += c5; // amount
    totalNewAmount += amt;
  }
  if (spkByHash.has(sh)) {
    matches.set(sh, {
      numSpent: Number(numSpent),
      numNew: Number(numNew),
      totalNewAmount,
    });
  }
  scanned++;
  if (scanned % 500000 === 0) {
    process.stderr.write(`\r  scanned ${scanned}/${numScripts}...`);
  }
}
process.stderr.write('\n');
console.log(`[info] Walked ${scanned} scripthashes; ${matches.size} matched the example SPKs`);

// ─── Keep every address with activity, report breakdown ───────────────────
//
// All three categories (spent-only, new-only, both) are good demo material.
// The web frontend's delta-activity renderer shows spent UTXOs with amounts
// looked up from the pre-delta snapshot, so testers can visually see "these
// UTXOs existed before, and the delta spent them" even when the merged view
// has zero remaining UTXOs.

let countSpentOnly = 0;
let countNewOnly = 0;
let countBoth = 0;
const intersection = [];
for (const [sh, info] of matches) {
  if (info.numSpent > 0 && info.numNew > 0) countBoth++;
  else if (info.numSpent > 0) countSpentOnly++;
  else if (info.numNew > 0) countNewOnly++;

  if (info.numSpent > 0 || info.numNew > 0) {
    intersection.push(spkByHash.get(sh));
  }
}

console.log(`[info] Match breakdown (all kept):`);
console.log(`         spent-only:  ${countSpentOnly}`);
console.log(`         new-only:    ${countNewOnly}`);
console.log(`         both:        ${countBoth}`);
console.log(`[info] Delta examples with visible activity: ${intersection.length}`);
if (intersection.length === 0) {
  console.error('[warn] Zero intersection — no main SPK had activity in this delta.');
}

// ─── Write back ─────────────────────────────────────────────────────────────
examples[deltaKey] = intersection;

// Canonical key order: main first, then deltas sorted by start height.
const orderedKeys = ['main'];
const deltaKeys = Object.keys(examples).filter(k => k.startsWith('delta_'))
  .sort((a, b) => {
    const [, aStart] = a.split('_').map(Number);
    const [, bStart] = b.split('_').map(Number);
    return aStart - bStart;
  });
orderedKeys.push(...deltaKeys);
const ordered = {};
for (const k of orderedKeys) if (examples[k]) ordered[k] = examples[k];

fs.writeFileSync(examplesPath, JSON.stringify(ordered, null, 2) + '\n');
console.log(`[info] Updated ${examplesPath}`);
console.log(`[info] Keys now: ${Object.keys(ordered).join(', ')}`);
