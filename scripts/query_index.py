#!/usr/bin/env python3
import struct
import hashlib
import argparse
from pathlib import Path
from bisect import bisect_left


class BitcoinIndexLookup:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.tx_index_file = self.data_dir / "tx_global_index.bin"
        self.spk_index_file = self.data_dir / "spk_global_index.bin"
        self.spk_lookup_file = self.data_dir / "spk_global_lookup.bin"
        self.meta_file = self.data_dir / "index_meta.json"

        self._load_metadata()

    def _load_metadata(self):
        import json

        if self.meta_file.exists():
            with open(self.meta_file, "r") as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {}

    def get_tx_by_index(self, tx_id):
        record_size = 18
        with open(self.tx_index_file, "rb") as f:
            offset = tx_id * record_size
            f.seek(offset)
            record = f.read(record_size)

        tx_id_decoded, block_height, tx_index, block_offset = struct.unpack(
            "<IH Q", record
        )

        return {
            "tx_id": tx_id_decoded,
            "block_height": block_height,
            "tx_index": tx_index,
            "block_offset": block_offset,
        }

    def get_all_tx_records(self):
        record_size = 18
        records = []

        with open(self.tx_index_file, "rb") as f:
            while True:
                record = f.read(record_size)
                if not record:
                    break

                tx_id, block_height, tx_index, block_offset = struct.unpack(
                    "<IH Q", record
                )
                records.append(
                    {
                        "tx_id": tx_id,
                        "block_height": block_height,
                        "tx_index": tx_index,
                        "block_offset": block_offset,
                    }
                )

        return records

    def get_spk_by_id(self, spk_id):
        with open(self.spk_index_file, "rb") as f:
            offset = 0

            for current_id in range(spk_id + 1):
                length_bytes = f.read(2)
                if not length_bytes:
                    return None

                length = struct.unpack("<H", length_bytes)[0]
                spk_bytes = f.read(length)

                if current_id == spk_id:
                    return {
                        "spk_id": spk_id,
                        "spk_hex": spk_bytes.hex(),
                        "length": length,
                    }

        return None

    def get_spk_id_by_hex(self, spk_hex):
        spk_hash = hashlib.sha256(bytes.fromhex(spk_hex)).digest()

        record_size = 34
        with open(self.spk_lookup_file, "rb") as f:
            while True:
                record = f.read(record_size)
                if not record:
                    return None

                stored_hash, spk_id = struct.unpack("<32sH", record)

                if stored_hash == spk_hash:
                    return spk_id

        return None

    def get_all_spk_records(self):
        records = []

        with open(self.spk_index_file, "rb") as f:
            spk_id = 0
            while True:
                length_bytes = f.read(2)
                if not length_bytes:
                    break

                length = struct.unpack("<H", length_bytes)[0]
                spk_bytes = f.read(length)

                records.append(
                    {"spk_id": spk_id, "spk_hex": spk_bytes.hex(), "length": length}
                )
                spk_id += 1

        return records

    def print_summary(self):
        print(f"Index Summary:")
        print(f"  Data directory: {self.data_dir}")

        if self.metadata:
            print(
                f"  Block range: {self.metadata.get('start_height', 'N/A')} - {self.metadata.get('end_height', 'N/A')}"
            )
            print(f"  Total blocks: {self.metadata.get('block_count', 'N/A')}")
            print(f"  Total transactions: {self.metadata.get('tx_count', 'N/A')}")
            print(
                f"  Total unique ScriptPubKeys: {self.metadata.get('spk_count', 'N/A')}"
            )

        tx_size = (
            self.tx_index_file.stat().st_size if self.tx_index_file.exists() else 0
        )
        spk_size = (
            self.spk_index_file.stat().st_size if self.spk_index_file.exists() else 0
        )
        lookup_size = (
            self.spk_lookup_file.stat().st_size if self.spk_lookup_file.exists() else 0
        )

        print(f"\nFile sizes:")
        print(
            f"  Transaction index: {tx_size:,} bytes ({tx_size / 1024 / 1024:.2f} MB)"
        )
        print(
            f"  ScriptPubKey index: {spk_size:,} bytes ({spk_size / 1024 / 1024:.2f} MB)"
        )
        print(
            f"  ScriptPubKey lookup: {lookup_size:,} bytes ({lookup_size / 1024 / 1024:.2f} MB)"
        )
        print(
            f"  Total: {tx_size + spk_size + lookup_size:,} bytes ({(tx_size + spk_size + lookup_size) / 1024 / 1024:.2f} MB)"
        )


def main():
    parser = argparse.ArgumentParser(description="Query Bitcoin indices")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    parser.add_argument("--summary", action="store_true", help="Print index summary")
    parser.add_argument("--get-tx", type=int, help="Get transaction by global ID")
    parser.add_argument(
        "--get-all-tx", action="store_true", help="List all transaction records"
    )
    parser.add_argument("--get-spk", type=int, help="Get ScriptPubKey by global ID")
    parser.add_argument("--get-spk-by-hex", help="Get ScriptPubKey ID by hex value")
    parser.add_argument(
        "--get-all-spk", action="store_true", help="List all ScriptPubKey records"
    )

    args = parser.parse_args()

    lookup = BitcoinIndexLookup(args.data_dir)

    if args.summary:
        lookup.print_summary()
    elif args.get_tx is not None:
        tx = lookup.get_tx_by_index(args.get_tx)
        if tx:
            print(f"Transaction {args.get_tx}:")
            print(f"  Block height: {tx['block_height']}")
            print(f"  TX index in block: {tx['tx_index']}")
            print(f"  Block offset: {tx['block_offset']}")
        else:
            print(f"Transaction {args.get_tx} not found")
    elif args.get_all_tx:
        txs = lookup.get_all_tx_records()
        print(f"Total transactions: {len(txs)}")
        for tx in txs[:10]:
            print(
                f"  TX {tx['tx_id']}: block={tx['block_height']}, index={tx['tx_index']}"
            )
        if len(txs) > 10:
            print(f"  ... and {len(txs) - 10} more")
    elif args.get_spk is not None:
        spk = lookup.get_spk_by_id(args.get_spk)
        if spk:
            print(f"ScriptPubKey {args.get_spk}:")
            print(f"  Hex: {spk['spk_hex']}")
            print(f"  Length: {spk['length']}")
        else:
            print(f"ScriptPubKey {args.get_spk} not found")
    elif args.get_spk_by_hex:
        spk_id = lookup.get_spk_id_by_hex(args.get_spk_by_hex)
        if spk_id is not None:
            print(f"ScriptPubKey hex → ID: {spk_id}")
        else:
            print(f"ScriptPubKey hex not found in index")
    elif args.get_all_spk:
        spks = lookup.get_all_spk_records()
        print(f"Total ScriptPubKeys: {len(spks)}")
        for spk in spks[:10]:
            print(
                f"  SPK {spk['spk_id']}: {spk['spk_hex'][:40]}{'...' if len(spk['spk_hex']) > 40 else ''} ({spk['length']} bytes)"
            )
        if len(spks) > 10:
            print(f"  ... and {len(spks) - 10} more")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
