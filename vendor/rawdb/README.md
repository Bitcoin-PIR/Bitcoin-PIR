# rawdb

Non-transactional embedded storage engine with a filesystem-like API.

It features:

- Multiple named regions in one file
- Automatic space reclamation via hole punching
- Regions grow and move automatically as needed
- Zero-copy mmap access
- Thread-safe with concurrent reads and writes
- Page-aligned allocations (4KB)
- Crash-consistent with explicit flush
- Foundation for higher-level abstractions (e.g., [`vecdb`](../vecdb/README.md))

It is not:

- A transactional database (no ACID, transactions, or rollback)
- A query engine (no SQL, indexes, or schemas)

## Install

```bash
cargo add rawdb
```

## Usage

```rust
use rawdb::{Database, Result};

fn main() -> Result<()> {
    // open database
    let temp_dir = tempfile::TempDir::new()?;
    let db = Database::open(temp_dir.path())?;

    // create regions
    let region1 = db.create_region_if_needed("region1")?;
    let region2 = db.create_region_if_needed("region2")?;

    // write data (buffered in mmap, not yet durable)
    region1.write(&[0, 1, 2, 3, 4])?;
    region2.write_at(&[5, 6, 7, 8, 9], 0)?;

    // flush to disk for durability
    db.flush()?;
    
    // read via mmap (data is immediately visible)
    {
        let reader = region1.create_reader();
        let _data = reader.read_all();
    } // reader dropped here, releasing its reference

    // remove region (space becomes reusable hole after flush)
    region1.remove()?;

    // punch holes in the file
    // db.compact()?; // doesn't work with doc-tests

    Ok(())
}
```

## Sparse files

rawdb relies on **sparse file** support. Files grow via `set_len()` which creates logical size without allocating physical blocks, and `compact()` punches holes to reclaim unused blocks. This means:

- The filesystem must support sparse files (ext4, XFS, APFS, ZFS, Btrfs — most modern filesystems do)
- `du` and `ls -s` show actual disk usage; `ls -l` shows the larger logical size
- Copying with `cp` may "densify" the file unless you use `cp --sparse=always` (Linux) or a sparse-aware tool
- Backups should use sparse-aware tools to avoid inflating archives

## Durability

Operations become durable after calling `flush()`. Before flush, writes are visible in memory but not guaranteed to survive crashes.

**Design:**
- **4KB metadata entries**: Atomic page-sized writes per region with embedded IDs
- **Single metadata file**: Rebuilt into HashMap on startup for O(1) lookups
- **No WAL**: Simple design with lazy flushing for consistency
- **Lazy writes**: Both data and metadata are written to mmaps immediately but not synced until flush

**Write model:**
1. **Data writes** modify the data mmap immediately (visible but not durable)
2. **Metadata changes** modify the metadata mmap immediately (visible but not durable)
3. **Holes from moves/removes** are marked as pending (not reusable until flush)
4. **`flush()`** syncs both mmaps (data → metadata → file size), then promotes pending holes
5. Ensures metadata never points to unflushed data and old locations aren't reused prematurely

**Region operations:**
- Expand in-place when possible (last region or adjacent hole)
- Copy-on-write to new location when expansion needed
- All changes visible immediately in mmaps, durable after `flush()`

**Recovery:**
On open, reads all metadata entries and rebuilds in-memory structures. Deleted regions are identified by zeroed metadata.
