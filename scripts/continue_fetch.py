#!/usr/bin/env python3
"""
Continue fetching Bitcoin blocks from a specific height.

Usage:
    python continue_fetch.py --start HEIGHT --count N

Options:
    --start HEIGHT  Starting block height (default: latest)
    --count N       Number of blocks to fetch (default: 100)
"""

import requests
import json
import os
import time
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# Configuration
BLOCKCYPER_API_BASE = "https://api.blockcypher.com/v1/btc/main"
DATA_DIR = "data"
BLOCKS_DIR = os.path.join(DATA_DIR, "blocks")
INDEX_FILE = os.path.join(DATA_DIR, "index.json")
REQUEST_DELAY = 0.2
RATE_LIMIT_DELAY = 3.0
MAX_RETRIES = 3

# Block metadata structure
BlockMetadata = Dict[str, Any]


def fetch_block_by_height(height: int) -> Optional[Dict[str, Any]]:
    """
    Fetch block by height using BlockCypher API with retry logic.
    """
    for attempt in range(MAX_RETRIES):
        try:
            url = f"{BLOCKCYPER_API_BASE}/blocks/{height}"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                wait_time = RATE_LIMIT_DELAY * (2**attempt)
                print(f"  ⚠ Rate limited, waiting {wait_time}s before retry...")
                time.sleep(wait_time)
            else:
                print(f"  ✗ HTTP error {e.response.status_code}: {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(REQUEST_DELAY * (attempt + 1))
                else:
                    return None
        except Exception as e:
            print(
                f"  ✗ Error fetching block (attempt {attempt + 1}/{MAX_RETRIES}): {e}"
            )
            if attempt < MAX_RETRIES - 1:
                time.sleep(REQUEST_DELAY * (attempt + 1))
            else:
                return None
    return None


def create_block_filename(index: int, height: Optional[int]) -> str:
    """Create a filename for a block file."""
    h = height if height is not None else 0
    return f"block_{h:06d}_{index:03d}.bin"


def save_block_json(block_json: dict, filename: str, blocks_dir: str) -> Optional[str]:
    """Save block data as JSON bytes to binary file."""
    filepath = os.path.join(blocks_dir, filename)
    try:
        json_bytes = json.dumps(block_json, separators=(",", ":")).encode("utf-8")
        with open(filepath, "wb") as f:
            f.write(json_bytes)
        return filepath
    except Exception as e:
        print(f"Error saving block to {filepath}: {e}")
        return None


def extract_block_metadata(block_json: dict, filename: str) -> BlockMetadata:
    """Extract metadata from block JSON response."""
    time_val = block_json.get("time", 0)
    try:
        if isinstance(time_val, str):
            from datetime import datetime as dt

            time_int = int(
                dt.fromisoformat(time_val.replace("Z", "+00:00")).timestamp()
            )
        else:
            time_int = int(time_val)
    except Exception:
        time_int = 0

    return {
        "hash": block_json.get("hash"),
        "height": block_json.get("height"),
        "timestamp": time_int,
        "size": block_json.get("size"),
        "prev_block": block_json.get("prev_block"),
        "merkle_root": block_json.get("merkle_root"),
        "tx_count": len(block_json.get("txids", [])),
        "file": filename,
    }


def load_existing_index() -> Dict[str, Any]:
    """Load existing index if it exists."""
    if os.path.exists(INDEX_FILE):
        try:
            with open(INDEX_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load existing index: {e}")
    return {"blocks": []}


def merge_with_existing_index(new_metadata: List[BlockMetadata]) -> List[BlockMetadata]:
    """Merge new blocks with existing index."""
    existing_index = load_existing_index()
    existing_blocks = existing_index.get("blocks", [])

    # Combine and sort by height descending
    all_blocks = existing_blocks + new_metadata
    sorted_blocks = sorted(all_blocks, key=lambda x: x.get("height", 0), reverse=True)

    return sorted_blocks


def fetch_blocks(
    start_height: Optional[int], count: int, verbose: bool = True
) -> List[BlockMetadata]:
    """
    Fetch specified number of blocks starting from a given height.
    """
    os.makedirs(BLOCKS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    # Determine starting height
    if start_height is None:
        # Fetch latest block
        if verbose:
            print(f"Fetching latest block to determine start height...")
        latest_url = f"{BLOCKCYPER_API_BASE}"
        response = requests.get(latest_url, timeout=30)
        response.raise_for_status()
        latest = response.json()
        current_height = latest.get("height")
    else:
        current_height = start_height

    if current_height is None:
        print("✗ Failed to determine starting height")
        return []

    if verbose:
        print(f"Starting from height: {current_height}")
        print(f"Fetching {count} blocks...")

    blocks_metadata = []

    for i in range(count):
        target_height = current_height - i

        if verbose:
            print(f"\n[{i + 1}/{count}] Fetching block at height {target_height}...")

        try:
            # Fetch block data
            block_json = fetch_block_by_height(target_height)

            if not block_json:
                print(f"  ✗ Failed to fetch block at height {target_height}")
                break

            # Save block data
            filename = create_block_filename(i, target_height)
            save_block_json(block_json, filename, BLOCKS_DIR)

            # Extract and store metadata
            metadata = extract_block_metadata(block_json, filename)
            blocks_metadata.append(metadata)

            if verbose:
                block_size = os.path.getsize(os.path.join(BLOCKS_DIR, filename))
                print(f"  ✓ Saved {filename} ({block_size} bytes)")
                block_hash = metadata.get("hash", "")[:16]
                print(f"    Hash: {block_hash}...")
                print(f"    Tx count: {metadata['tx_count']}")

            # Rate limiting
            time.sleep(REQUEST_DELAY)

        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            break

    # Merge with existing index
    final_metadata = merge_with_existing_index(blocks_metadata)

    return final_metadata


def save_index(blocks_metadata: List[BlockMetadata]) -> None:
    """Save block metadata to index.json."""
    index_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_blocks": len(blocks_metadata),
        "blocks": blocks_metadata,
    }

    with open(INDEX_FILE, "w") as f:
        json.dump(index_data, f, indent=2)

    print(f"\n✓ Saved index to {INDEX_FILE} ({len(blocks_metadata)} blocks)")


def print_summary(blocks_metadata: List[BlockMetadata]) -> None:
    """Print summary of fetched blocks."""
    if not blocks_metadata:
        print("\nNo blocks in index!")
        return

    print("\n" + "=" * 60)
    print("FETCH SUMMARY")
    print("=" * 60)
    print(f"Total blocks in index: {len(blocks_metadata)}")

    if len(blocks_metadata) > 0:
        first = blocks_metadata[0]
        last = blocks_metadata[-1]

        first_height = first.get("height")
        last_height = last.get("height")

        if first_height is not None and last_height is not None:
            print(f"Height range: {first_height} → {last_height}")

        sizes = [m.get("size", 0) for m in blocks_metadata if m.get("size") is not None]
        total_size = sum(sizes)
        avg_size = total_size / len(sizes) if sizes else 0
        print(f"Total size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
        print(f"Average block size: {avg_size:,.0f} bytes")

        tx_counts = [
            m.get("tx_count", 0)
            for m in blocks_metadata
            if m.get("tx_count") is not None
        ]
        total_tx = sum(tx_counts)
        print(f"Total transactions: {total_tx:,}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Continue fetching Bitcoin blocks from a specific height"
    )
    parser.add_argument(
        "--start", type=int, help="Starting block height (default: latest)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of blocks to fetch (default: 100)",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")

    args = parser.parse_args()

    verbose = not args.quiet

    print("Bitcoin Block Continuation Fetcher")
    print("=" * 60)

    # Calculate starting height for remaining blocks
    existing_index = load_existing_index()
    existing_count = len(existing_index.get("blocks", []))

    if existing_count >= 100:
        print(f"✓ Already have {existing_count} blocks. No need to fetch more.")
        print_summary(existing_index.get("blocks", []))
        return

    remaining = 100 - existing_count

    if args.start is None:
        # Determine next height to fetch
        if existing_count > 0:
            last_block = existing_index["blocks"][0]
            start_height = last_block.get("height") - 1
            print(
                f"Continuing from height {start_height} (have {existing_count} blocks)"
            )
        else:
            start_height = None
    else:
        start_height = args.start

    count = min(args.count, remaining)

    if verbose:
        print(f"Fetching {count} more blocks...")
        print(f"Target: 100 blocks total")

    # Fetch blocks
    blocks_metadata = fetch_blocks(start_height, count, verbose=verbose)

    # Save index
    save_index(blocks_metadata)

    # Print summary
    if verbose:
        print_summary(blocks_metadata)

    total_now = len(blocks_metadata)
    if total_now >= 100:
        print(f"\n✅✅✅ Phase 1 COMPLETE! All 100 blocks fetched!")
    else:
        print(f"\n⚠ Progress: {total_now}/100 blocks ({total_now}%)")
        print(f"    Run again in ~30 seconds to fetch more blocks")


if __name__ == "__main__":
    main()
