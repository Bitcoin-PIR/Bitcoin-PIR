//! Generic consistency tests for all vec types.

use rawdb::Database;
use tempfile::TempDir;
use vecdb::{AnyStoredVec, EagerVec, ImportableVec, ReadableVec, StoredVec, Version, WritableVec};

// ============================================================================
// Generic Test Functions
// ============================================================================

/// Generic test function for mmap write/file read consistency
fn run_mmap_write_file_read_consistency<V>()
where
    V: StoredVec<I = usize, T = u64>,
{
    let temp_dir = TempDir::new().unwrap();
    let db = Database::open(&temp_dir.path().join("test.db")).unwrap();

    // Create a vec (which uses mmap for writes)
    let mut vec: EagerVec<V> = EagerVec::forced_import(&db, "test_vec", Version::ONE).unwrap();

    // Write some data
    for i in 0..1000usize {
        vec.checked_push_at(i, i as u64 * 100).unwrap();
    }

    // Flush the vec (writes to mmap)
    vec.flush().unwrap();

    println!("After flush, checking data consistency...");

    // Check if collected data matches what was written
    let collected = vec.collect();
    (0..1000usize).for_each(|i| {
        let value = collected[i];
        let expected = i as u64 * 100;

        if value != expected {
            panic!(
                "Inconsistency detected at index {}: got {}, expected {}",
                i, value, expected
            );
        }
    });

    println!("Test passed! All values consistent.");
}

/// Generic test function for immediate read after write
fn run_immediate_read_after_write<V>()
where
    V: StoredVec<I = usize, T = u64>,
{
    let temp_dir = TempDir::new().unwrap();
    let db = Database::open(&temp_dir.path().join("test2.db")).unwrap();

    let mut vec: EagerVec<V> = EagerVec::forced_import(&db, "test_vec", Version::ONE).unwrap();

    // Write, flush, read immediately (mimics the txinindex -> txindex pattern)
    for batch in 0..10 {
        let start = batch * 100;

        // Write batch
        for i in 0..100usize {
            vec.checked_push_at(start + i, (start + i) as u64 * 100)
                .unwrap();
        }

        // Flush
        vec.flush().unwrap();

        // Immediately read back using collect_range
        for i in 0..100usize {
            let idx = start + i;
            let value = vec.collect_one(idx).unwrap();
            let expected = (start + i) as u64 * 100;

            if value != expected {
                panic!(
                    "Batch {} inconsistency at index {}: got {}, expected {}",
                    batch, idx, value, expected
                );
            }
        }
    }

    println!("Immediate read test passed!");
}

// ============================================================================
// Test instantiation for BytesVec (no feature flag needed)
// ============================================================================

mod bytes {
    use super::*;
    use vecdb::BytesVec;
    type V = BytesVec<usize, u64>;

    #[test]
    fn mmap_write_file_read_consistency() {
        run_mmap_write_file_read_consistency::<V>();
    }

    #[test]
    fn immediate_read_after_write() {
        run_immediate_read_after_write::<V>();
    }
}

// ============================================================================
// Test instantiation for feature-gated vec types
// ============================================================================

#[cfg(feature = "zerocopy")]
mod zerocopy {
    use super::*;
    use vecdb::ZeroCopyVec;
    type V = ZeroCopyVec<usize, u64>;

    #[test]
    fn mmap_write_file_read_consistency() {
        run_mmap_write_file_read_consistency::<V>();
    }

    #[test]
    fn immediate_read_after_write() {
        run_immediate_read_after_write::<V>();
    }
}

#[cfg(feature = "pco")]
mod pco {
    use super::*;
    use vecdb::PcoVec;
    type V = PcoVec<usize, u64>;

    #[test]
    fn mmap_write_file_read_consistency() {
        run_mmap_write_file_read_consistency::<V>();
    }

    #[test]
    fn immediate_read_after_write() {
        run_immediate_read_after_write::<V>();
    }
}

#[cfg(feature = "lz4")]
mod lz4 {
    use super::*;
    use vecdb::LZ4Vec;
    type V = LZ4Vec<usize, u64>;

    #[test]
    fn mmap_write_file_read_consistency() {
        run_mmap_write_file_read_consistency::<V>();
    }

    #[test]
    fn immediate_read_after_write() {
        run_immediate_read_after_write::<V>();
    }
}

#[cfg(feature = "zstd")]
mod zstd {
    use super::*;
    use vecdb::ZstdVec;
    type V = ZstdVec<usize, u64>;

    #[test]
    fn mmap_write_file_read_consistency() {
        run_mmap_write_file_read_consistency::<V>();
    }

    #[test]
    fn immediate_read_after_write() {
        run_immediate_read_after_write::<V>();
    }
}
