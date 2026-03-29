#!/usr/bin/env python3
"""
Mock wallet test for PirSynchronizer.

Exercises the full stack without needing Electrum on sys.path:
  MockWallet → PirSynchronizer → BatchPirClient → ws://127.0.0.1:8091/8092

The only Electrum dependency in the synchronizer is `address_to_script`
from electrum.bitcoin.  We stub that out with a minimal pure-Python
implementation so the test runs against any Python 3.9+ installation.

Requires:
  - DPF servers running on 127.0.0.1:8091 / 8092
  - websockets + cryptography Python packages installed
"""

import asyncio
import hashlib
import logging
import sys
import time
import types

# ── Minimal electrum.bitcoin stub ────────────────────────────────────────────
#
# The synchronizer calls:
#   from electrum.bitcoin import address_to_script
#   spk_hex = address_to_script(address)
#
# We inject a real implementation before any pir_privacy import happens.

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _b58check_decode(s):
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    pad = len(s) - len(s.lstrip('1'))
    raw = b'\x00' * pad + (n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b'')
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError('bad checksum')
    return raw[0], raw[1:-4]


def _bech32_polymod(vals):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in vals:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk


def _bech32_decode(bech):
    bech = bech.lower()
    pos = bech.rfind('1')
    hrp, data = bech[:pos], [_BECH32.find(x) for x in bech[pos + 1:]]
    expand = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    if _bech32_polymod(expand + data) != 1:
        return None, None
    return hrp, data[:-6]


def _convertbits(data, frombits, tobits):
    acc, bits, out = 0, 0, []
    for v in data:
        acc = ((acc << frombits) | v) & ((1 << (frombits + tobits - 1)) - 1)
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & ((1 << tobits) - 1))
    return bytes(out)


def _address_to_script(addr: str) -> str:
    """Return scriptPubKey hex for a mainnet Bitcoin address."""
    if addr.lower().startswith('bc1'):
        _, data = _bech32_decode(addr)
        prog = _convertbits(data[1:], 5, 8)
        if data[0] == 0 and len(prog) == 20:          # P2WPKH
            return '0014' + prog.hex()
        if data[0] == 0 and len(prog) == 32:          # P2WSH
            return '0020' + prog.hex()
        raise ValueError(f'Unknown witness program: {addr}')
    ver, payload = _b58check_decode(addr)
    if ver == 0x00:                                    # P2PKH
        return '76a914' + payload.hex() + '88ac'
    if ver == 0x05:                                    # P2SH
        return 'a914' + payload.hex() + '87'
    raise ValueError(f'Unknown address version 0x{ver:02x}: {addr}')


# Inject stub modules before pir_privacy imports them
_electrum_mod = types.ModuleType('electrum')
_bitcoin_mod  = types.ModuleType('electrum.bitcoin')
_bitcoin_mod.address_to_script = _address_to_script
_electrum_mod.bitcoin = _bitcoin_mod
sys.modules['electrum']        = _electrum_mod
sys.modules['electrum.bitcoin'] = _bitcoin_mod

# ── Now safe to import pir_privacy ───────────────────────────────────────────

sys.path.insert(0, '/Users/cusgadmin/BitcoinPIR/electrum_plugin')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(message)s',
    datefmt='%H:%M:%S',
)

# ── Mock wallet ───────────────────────────────────────────────────────────────

class MockAdb:
    class db:
        @staticmethod
        def get_transaction(_txid_hex):
            return None   # no existing txs — synchronizer logs UTXOs only


class MockWallet:
    """
    Minimal stub of Electrum's Abstract_Wallet.

    Three test addresses covering P2WPKH, P2PKH and P2SH script types.
    """
    adb = MockAdb()

    ADDRESSES = [
        'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',  # P2WPKH — has UTXOs
        '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',          # P2PKH  — has UTXOs
        '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',           # P2SH   — may be empty
    ]

    def get_addresses(self):
        return self.ADDRESSES


class MockPlugin:
    pass


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    from pir_privacy.pir_client import BatchPirClient
    from pir_privacy.pir_synchronizer import PirSynchronizer

    print('╔══════════════════════════════════════════════════════════╗')
    print('║   Mock Wallet → PirSynchronizer → DPF PIR Servers       ║')
    print('╚══════════════════════════════════════════════════════════╝')

    # ── 1. Connect PIR client ────────────────────────────────────────────────
    print('\n[1] Connecting to PIR servers...')
    client = BatchPirClient('ws://127.0.0.1:8091', 'ws://127.0.0.1:8092')
    t0 = time.time()
    await client.connect()
    print(f'    Connected in {time.time() - t0:.2f}s')
    print(f'    index_bins={client.index_bins}  chunk_bins={client.chunk_bins}')
    print(f'    tag_seed=0x{client.tag_seed:016x}')

    # ── 2. Create synchronizer ───────────────────────────────────────────────
    wallet = MockWallet()
    sync = PirSynchronizer(wallet, MockPlugin(), sync_interval=60.0)

    print(f'\n[2] Starting PirSynchronizer for {len(wallet.ADDRESSES)} addresses:')
    for addr in wallet.ADDRESSES:
        print(f'    {addr}')

    # ── 3. Run one sync cycle ────────────────────────────────────────────────
    t_sync = time.time()
    await sync.start(client)

    # The loop fires an initial sync immediately; wait for _last_sync_time to be set.
    print('\n[3] Waiting for initial sync...')
    for _ in range(180):          # up to 3 minutes
        await asyncio.sleep(1)
        if sync._last_sync_time > 0:
            break
    else:
        print('    TIMEOUT — sync did not complete')
        sync.stop()
        await client.disconnect()
        sys.exit(1)

    sync.stop()
    elapsed = time.time() - t_sync

    # ── 4. Summary ───────────────────────────────────────────────────────────
    status = sync.get_status()
    total_sats = status['total_sats']

    print(f'\n[4] Sync completed in {elapsed:.1f}s')
    print(f'    Addresses queried:    {status["total_addresses"]}')
    print(f'    Addresses with UTXOs: {status["addresses_with_utxos"]}')
    print(f'    Total UTXOs:          {status["total_utxos"]}')
    print(f'    Total balance:        {total_sats} sats  ({total_sats / 1e8:.8f} BTC)')

    # ── 5. Per-address breakdown ─────────────────────────────────────────────
    print('\n[5] Per-address breakdown:')
    for addr in wallet.ADDRESSES:
        utxos = sync._last_utxo_snapshot.get(addr, [])
        addr_sats = sum(amt for _, _, amt in utxos)
        if utxos:
            print(f'\n    ✓ {addr}')
            print(f'      {len(utxos)} UTXOs  —  {addr_sats} sats  ({addr_sats / 1e8:.8f} BTC)')
            for txid_bytes, vout, amount in utxos[:5]:
                print(f'      {txid_bytes[::-1].hex()[:20]}...:{vout}  {amount} sats')
            if len(utxos) > 5:
                print(f'      ... and {len(utxos) - 5} more')
        else:
            print(f'\n    ○ {addr}  — no UTXOs found')

    # ── 6. Teardown ──────────────────────────────────────────────────────────
    await client.disconnect()

    print('\n' + '═' * 60)
    if status['addresses_with_utxos'] > 0:
        print('  RESULT: PASS ✓  —  PirSynchronizer found UTXOs via PIR')
    else:
        print('  RESULT: WARN  —  no UTXOs found (check servers / addresses)')
    print('═' * 60)

    if status['addresses_with_utxos'] == 0:
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
