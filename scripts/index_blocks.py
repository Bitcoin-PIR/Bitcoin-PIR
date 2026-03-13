#!/usr/bin/env python3
import struct
import hashlib
import json
import argparse
import os
from pathlib import Path


class BitcoinIndexer:
    def __init__(self, rpc_url, rpc_user, rpc_password, data_dir="data"):
        self.rpc_url = rpc_url
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.tx_counter = 0
        self.spk_counter = 0
        self.spk_lookup = {}

        self.tx_index_file = self.data_dir / "tx_global_index.bin"
        self.spk_index_file = self.data_dir / "spk_global_index.bin"
        self.spk_lookup_file = self.data_dir / "spk_global_lookup.bin"

    def get_block_hash(self, height):
        import requests

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getblockhash",
            "params": [height],
        }
        response = requests.post(
            self.rpc_url,
            json=payload,
            auth=(self.rpc_user, self.rpc_password),
            timeout=30,
        )
        result = response.json()
        if "error" in result and result["error"]:
            raise Exception(f"RPC error: {result['error']}")
        return result["result"]

    def get_block(self, block_hash):
        import requests

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getblock",
            "params": [block_hash, 2],
        }
        response = requests.post(
            self.rpc_url,
            json=payload,
            auth=(self.rpc_user, self.rpc_password),
            timeout=30,
        )
        result = response.json()
        if "error" in result and result["error"]:
            raise Exception(f"RPC error: {result['error']}")
        return result["result"]

    def hash_spk(self, spk_hex):
        return hashlib.sha256(bytes.fromhex(spk_hex)).digest()

    def get_or_create_spk_id(self, spk_hex):
        spk_hash = self.hash_spk(spk_hex)

        if spk_hash in self.spk_lookup:
            return self.spk_lookup[spk_hash]

        if self.spk_counter >= 65535:
            raise Exception("SPK counter overflow: too many unique ScriptPubKeys")

        spk_id = self.spk_counter
        self.spk_counter += 1
        self.spk_lookup[spk_hash] = spk_id
        return spk_id

    def write_tx_record(self, block_height, tx_index, block_offset):
        record = struct.pack(
            "<IH Q", self.tx_counter, block_height, tx_index, block_offset
        )
        self.tx_counter += 1
        return record

    def write_spk_record(self, spk_hex, spk_id):
        spk_bytes = bytes.fromhex(spk_hex)
        length = len(spk_bytes)
        record = struct.pack(f"<H{length}s", length, spk_bytes)
        return record

    def write_spk_lookup_record(self, spk_hash, spk_id):
        return struct.pack("<32sH", spk_hash, spk_id)

    def index_block(self, block_data):
        block_height = block_data["height"]
        txs = block_data.get("tx", [])

        tx_records = []
        spk_records = {}
        spk_lookup_records = []

        for tx_index, tx in enumerate(txs):
            txid = tx["txid"]

            tx_record = self.write_tx_record(block_height, tx_index, 0)
            tx_records.append((txid, tx_record))

            for output in tx.get("vout", []):
                scriptpubkey = output.get("scriptPubKey", {})
                spk_hex = scriptpubkey.get("hex", "")

                if spk_hex:
                    spk_id = self.get_or_create_spk_id(spk_hex)
                    spk_hash = self.hash_spk(spk_hex)

                    if spk_id not in spk_records:
                        spk_records[spk_id] = (
                            spk_hex,
                            self.write_spk_record(spk_hex, spk_id),
                        )

                    spk_lookup_records.append(
                        self.write_spk_lookup_record(spk_hash, spk_id)
                    )

        return tx_records, spk_records, spk_lookup_records

    def save_indices(self, tx_records, spk_records, spk_lookup_records):
        with open(self.tx_index_file, "ab") as f:
            for txid, record in tx_records:
                f.write(record)

        with open(self.spk_index_file, "ab") as f:
            for spk_id, (spk_hex, record) in sorted(spk_records.items()):
                f.write(record)

        with open(self.spk_lookup_file, "ab") as f:
            f.write(b"".join(spk_lookup_records))

    def reset_indices(self):
        for f in [self.tx_index_file, self.spk_index_file, self.spk_lookup_file]:
            if f.exists():
                f.unlink()
        self.tx_counter = 0
        self.spk_counter = 0
        self.spk_lookup = {}

    def write_metadata(self, start_height, end_height):
        metadata = {
            "tx_count": self.tx_counter,
            "spk_count": self.spk_counter,
            "start_height": start_height,
            "end_height": end_height,
            "block_count": end_height - start_height + 1,
        }

        meta_file = self.data_dir / "index_meta.json"
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Index Bitcoin blocks for PIR queries")
    parser.add_argument(
        "--rpc-url",
        default="http://127.0.0.1:18332",
        help="Bitcoin RPC URL (default: testnet)",
    )
    parser.add_argument("--rpc-user", required=True, help="Bitcoin RPC username")
    parser.add_argument("--rpc-password", required=True, help="Bitcoin RPC password")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    parser.add_argument("--start-height", type=int, help="Starting block height")
    parser.add_argument(
        "--count", type=int, default=100, help="Number of blocks to index"
    )
    parser.add_argument(
        "--from-tip",
        action="store_true",
        help="Index from the latest block tip backwards",
    )
    parser.add_argument(
        "--reset", action="store_true", help="Reset existing indices before starting"
    )

    args = parser.parse_args()

    indexer = BitcoinIndexer(
        args.rpc_url, args.rpc_user, args.rpc_password, args.data_dir
    )

    if args.reset:
        print("Resetting existing indices...")
        indexer.reset_indices()

    try:
        import requests

        payload = {"jsonrpc": "2.0", "id": 1, "method": "getblockcount"}
        response = requests.post(
            args.rpc_url,
            json=payload,
            auth=(args.rpc_user, args.rpc_password),
            timeout=30,
        )
        latest_height = response.json()["result"]
    except Exception as e:
        print(f"Error getting block count: {e}")
        return

    if args.from_tip:
        start_height = latest_height - args.count + 1
    elif args.start_height is not None:
        start_height = args.start_height
    else:
        start_height = latest_height - args.count + 1

    end_height = start_height + args.count - 1

    print(f"Indexing blocks {start_height} to {end_height} (total {args.count} blocks)")
    print(f"Latest block: {latest_height}")

    total_tx_records = []
    total_spk_records = {}
    total_spk_lookup_records = []

    for height in range(start_height, end_height + 1):
        try:
            block_hash = indexer.get_block_hash(height)
            block_data = indexer.get_block(block_hash)

            tx_records, spk_records, spk_lookup_records = indexer.index_block(
                block_data
            )

            total_tx_records.extend(tx_records)
            total_spk_records.update(spk_records)
            total_spk_lookup_records.extend(spk_lookup_records)

            if height % 10 == 0:
                print(
                    f"Processed block {height}/{end_height} ({indexer.tx_counter} TXs, {indexer.spk_counter} SPKs)"
                )

        except Exception as e:
            print(f"Error processing block {height}: {e}")
            continue

    indexer.save_indices(total_tx_records, total_spk_records, total_spk_lookup_records)
    indexer.write_metadata(start_height, end_height)

    print(f"\nIndexing complete!")
    print(f"  Total transactions indexed: {indexer.tx_counter}")
    print(f"  total unique ScriptPubKeys: {indexer.spk_counter}")
    print(f"  Transaction index: {indexer.tx_index_file}")
    print(f"  ScriptPubKey index: {indexer.spk_index_file}")
    print(f"  ScriptPubKey lookup: {indexer.spk_lookup_file}")


if __name__ == "__main__":
    main()
