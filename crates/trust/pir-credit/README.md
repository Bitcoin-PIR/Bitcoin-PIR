# pir-credit

Credits and gas for BitcoinPIR paid queries (design: `docs/CREDITS.md`).

- `gas`: the gas model. One gas is one CPU-millisecond of work on the
  reference machine (pir1, Intel i7-8700, all threads). Every metered
  request kind has a formula in public database geometry (bins, groups,
  table bytes, NTT bytes, ORAM slots) calibrated against measurements taken
  on 2026-09-09, so a database of any size prices itself and a provider
  running different hardware only changes its price per gas.
- `params`: the issuer-published parameters that turn gas into credits
  (`gas_per_credit`, the per-frame base fee, the egress term) and the
  credit ↔ sat ↔ gas conversions.
- `meter`: the hourly per-opcode aggregate a server logs (count, gas, CPU
  and wall time, egress, concurrency) — aggregates only, never per request.
- `issuer`: the JSON types of the issuer HTTP contract (`/v2/info` and
  `/v2/redeem`) and the canonical signing preimages of a redeem request and
  its answer.

Pure bookkeeping: no cryptography, filesystem, clock, or network.
