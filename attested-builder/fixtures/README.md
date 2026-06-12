# attested-builder fixtures

Golden data for Phase 1 (`utxosnapshot` parser + muhash verification).
Produced 2026-06-12 against the owner's Bitcoin node. All values below
are exact strings copied from `bitcoin-cli` output — the end-to-end
golden test must reproduce the muhash **display hex** byte-for-byte.

Core version for both fixtures: **Bitcoin Core v31.0.0**
(`getnetworkinfo` version `310000`, subversion `/Satoshi:31.0.0/`;
macOS, Homebrew; `dumptxoutset` v2 snapshot format, Core ≥ 28).

---

## 1. Regtest golden fixture (committed here)

File: [`txoutset_regtest_111.dat`](txoutset_regtest_111.dat) (6,861 bytes,
committed — this is the end-to-end test input).

| field | value |
|---|---|
| network | regtest (snapshot network magic `fa bf b5 da`) |
| height | `111` |
| best block hash | `4e4003e955a41b187ad32e26fc837a98ca284df84ca3bbea19e6d164b3ebb3e7` |
| **muhash** | `5b93564046e31a3798231c767eb24e45dd818b77ae022cbe8861e2af9d4a8c09` |
| txouts (coins) | `115` |
| transactions | `113` |
| total_amount | `5550.00000000` |
| bogosize | `8307` |
| `dumptxoutset` coins_written | `115` |
| `dumptxoutset` txoutset_hash | `6ee94e37ca1eeeb0a2905575cd9865ba4a4f5c5b37204c75e67985105b16501b` |
| `dumptxoutset` nchaintx | `117` |
| file sha256 | `c9a51490adb3ce8e89bbf767ec387d21911d954bd819e0338ec4613227ed3a93` |

`muhash` / height / best block / txouts are from
`gettxoutsetinfo muhash` at tip; the `dumptxoutset` row values are from
the `dumptxoutset <path> latest` JSON result (its `base_hash` /
`base_height` matched the same block, `txoutset_hash` is Core's
`hash_serialized_3`, *not* muhash).

Header sanity (first bytes of the file): `7574786f ff` (`utxo\xff`
magic) ‖ `0200` (version 2, LE u16) ‖ `fabfb5da` (regtest message
magic) ‖ 32-byte base block hash (LE — reverses to the display hash
above) ‖ `7300000000000000` (coin count 115, LE u64).

### How it was generated (reproducible recipe, not byte-reproducible)

Throwaway datadir, `bitcoind -regtest -fallbackfee=0.0001 -txindex=1`:

1. `createwallet fixture`; mine 101 blocks to a fresh bech32 address
   (coinbase maturity).
2. Send 4 transactions to fresh wallet addresses of distinct types:
   1.0 BTC → p2wpkh (bech32), 2.0 → **p2tr** (bech32m), 0.5 → **legacy
   p2pkh**, 0.25 → **p2sh-segwit**; mine 1 block (height 102). The
   sends chain off each other's unconfirmed outputs, so the 1.0 p2wpkh
   output and its change are both **spent** by later txs — the set has
   real non-coinbase spends and change outputs.
3. Send a 5th tx, 0.33 → fresh **p2wpkh**, mine 1 block + 7 more
   (height 111).
4. `gettxoutsetinfo muhash`, then
   `dumptxoutset <path> latest`, then `shasum -a 256`.

Final set: 115 coins = 111 coinbase outputs (p2wpkh) + unspent
receives (p2tr 2.0, legacy 0.5, p2sh-segwit 0.25, p2wpkh 0.33) +
wallet change (p2wpkh). Script-compression coverage: case 0 (p2pkh),
case 1 (p2sh), and the raw-script fallback (p2wpkh, p2tr), plus
amount compression across many magnitudes and VARINT heights/coinbase
flags. NOT covered: P2PK cases 2–5 (no P2PK outputs here) — the
`utxosnapshot` unit tests should take those from Core's
`compress_tests.cpp` vectors as PLAN.md Phase 1 step 1 already calls
for.

Note: the fixture is **recipe-reproducible, not byte-reproducible** —
wallet keys, txids and the muhash differ on every regeneration. The
committed `.dat` + the strings above are the canonical golden pair.

---

## 2. Mainnet anchor snapshot (metadata only — file stays on the SSD)

File (NOT committed): `/Volumes/Bitcoin/data/archive/txoutset_953383.dat`

| field | value |
|---|---|
| network | mainnet |
| anchor height | `953383` (tip 953389 − 6 at capture time) |
| anchor block hash | `00000000000000000001d1ef626ec834feeb2aee2c9a1ec130d4b430337125e1` |
| **muhash** | `adbbcf0147d6a651cae435bece956566c091a3eaa45a8ddd070bbf437fbe8880` |
| txouts (coins) | `165743625` |
| transactions | `114753780` |
| total_amount | `20041594.88997129` |
| bogosize | `12982949293` |
| `dumptxoutset` coins_written | `165743625` (== txouts above — same state) |
| `dumptxoutset` txoutset_hash | `64c9a2c9214e32389484765eff4c3617abf5277118278c2727f141846a80c347` |
| `dumptxoutset` nchaintx | `1375068330` |
| file sha256 | `109dbb62d959d1e42faf3577523d30823fab8346846b5c959bf7f7fb87f49d59` |
| file size | `9470351881` bytes |

Method note: this node runs without `-coinstatsindex`, so
`gettxoutsetinfo muhash <height>` is unavailable. The anchor muhash
was computed by `invalidateblock <hash(anchor+1)>` →
`gettxoutsetinfo muhash` (tip == anchor) → `reconsiderblock` — the
same temporary-rollback semantics `dumptxoutset rollback=<height>`
uses internally. The snapshot itself was produced with
`bitcoin-cli -rpcclienttimeout=0 -named dumptxoutset <path>
rollback=953383`.

---

## 3. gen_1_onion dust/whale counts (PLAN.md node-task 4)

Re-run 2026-06-12 with `gen_1_onion --data-dir <fresh dir>` (binary
from this branch; OnionPIR entry size 3328 B, 4 partitions) against
**`/Volumes/Bitcoin/data/intermediate/full_948454/utxo_set.bin`** —
the current production full snapshot, **height 948454** (built
2026-05-24). These counts size the documented filter for *that*
snapshot, not the new 953383 anchor above; outputs were written to a
scratch dir and discarded, only the printed stats were kept (they were
never persisted by the original build — that's node-task 4).

Input: `164832143` UTXO entries (11.21 GB raw, 68 B/entry).

| partition | unique script_hashes | dust skipped (≤ 576 sats) | whale (> 100 UTXOs/SPK) |
|---|---|---|---|
| 1 | 13,456,535 | 16,764,702 | 9,857 |
| 2 | 13,464,804 | 18,717,875 | 9,900 |
| 3 | 13,458,270 | 16,385,562 | 9,736 |
| 4 | 13,455,430 | 16,877,381 | 9,974 |
| **total** | **53,835,039** | **68,745,520** | **39,467** |

- *dust skipped* counts individual UTXOs with amount ≤ 576 sats,
  dropped before grouping (`DUST_THRESHOLD` in
  `build/src/gen_1_onion.rs`).
- *unique script_hashes* counts SPK groups with ≥ 1 non-dust UTXO
  (164,832,143 − 68,745,520 = 96,086,623 surviving UTXOs, ≈ 1.79 per
  SPK). Matches the index file's 53,835,039 entries.
- *whale* counts SPK groups exceeding `MAX_UTXOS_PER_SPK = 100`,
  written as sentinel index entries (`FLAG_WHALE`, no chunk data).
- Packed output (discarded): 948,640 OnionPIR entries × 3328 B
  (3.16 GB), 5,100 groups > 3840 B spanning multiple entries (0.01 %).

These are the numbers the `rootbundle` filter-params docs should cite
for the 576-sat dust threshold and 100-UTXO whale cap.
