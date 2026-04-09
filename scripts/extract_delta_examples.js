#!/usr/bin/env node
/**
 * Extract "example SPKs that produce a visibly positive change in a delta"
 * and update web/src/example_spks.json with a per-delta list.
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
 *   4. Filters the intersection to addresses with `num_new > 0` — these
 *      add at least one new UTXO that's still unspent at the delta's tip
 *      height, so the post-merge view in the web sync flow is guaranteed
 *      to show a visible "+UTXO appeared" effect. Spent-only addresses
 *      are excluded because the merged view of an address whose only
 *      UTXOs were spent shows zero UTXOs, which testers misread as
 *      "the delta did nothing".
 *   5. Writes the filtered list back to web/src/example_spks.json under
 *      the key `delta_<A>_<B>`. Also reports the breakdown (spent-only,
 *      new-only, both) for transparency.
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

// ─── Apply demo-friendly filter ────────────────────────────────────────────
//
// Keep only addresses with `numNew > 0`. These guarantee the post-merge
// view in the web sync flow shows MORE UTXOs at the delta's tip height
// than at the base height — a clear "+UTXO appeared" signal that testers
// can observe even without seeing the spent-list breakdown.
//
// Spent-only addresses are excluded because if `numSpent` reaches the
// address's main UTXO count (which is the typical case for small
// addresses), the merged result has zero UTXOs and reads as "the delta
// did nothing".

let countSpentOnly = 0;
let countNewOnly = 0;
let countBoth = 0;
const intersection = [];
for (const [sh, info] of matches) {
  if (info.numSpent > 0 && info.numNew > 0) countBoth++;
  else if (info.numSpent > 0) countSpentOnly++;
  else if (info.numNew > 0) countNewOnly++;

  if (info.numNew > 0) {
    intersection.push(spkByHash.get(sh));
  }
}

console.log(`[info] Match breakdown:`);
console.log(`         spent-only:  ${countSpentOnly}  (excluded)`);
console.log(`         new-only:    ${countNewOnly}  (kept)`);
console.log(`         both:        ${countBoth}  (kept)`);
console.log(`[info] Demo-friendly examples (numNew > 0): ${intersection.length}`);
if (intersection.length === 0) {
  console.error('[warn] Zero demo-friendly examples — no main SPK gained a new UTXO in this delta.');
  console.error('       Consider sampling more SPKs into example_spks.json["main"].');
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
