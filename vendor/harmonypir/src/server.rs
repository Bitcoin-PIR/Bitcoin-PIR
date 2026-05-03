//! PIR server.
//!
//! The server holds the database and responds to client requests.
//! For each request Q (a list of T indices), the server returns the
//! database entries at those indices. Empty indices (EMPTY sentinel)
//! get a zero response.

use crate::relocation::EMPTY;
use crate::util::zero_entry;

/// The PIR server holding the database.
pub struct Server {
    /// The database: N entries, each of w bytes.
    db: Vec<Vec<u8>>,
    /// Entry size in bytes.
    w: usize,
}

impl Server {
    /// Create a server with the given database.
    ///
    /// All entries must have the same size.
    pub fn new(db: Vec<Vec<u8>>) -> Self {
        let w = db.first().map_or(0, |e| e.len());
        assert!(db.iter().all(|e| e.len() == w), "all entries must have equal size");
        Server { db, w }
    }

    /// Answer a client request.
    ///
    /// `request` is a list of T indices (some may be EMPTY).
    /// Returns a list of T entries: DB[q[i]] for non-empty indices, zero for EMPTY.
    pub fn answer(&self, request: &[usize]) -> Vec<Vec<u8>> {
        request
            .iter()
            .map(|&idx| {
                if idx == EMPTY {
                    zero_entry(self.w)
                } else {
                    assert!(idx < self.db.len(), "request index {idx} out of range");
                    self.db[idx].clone()
                }
            })
            .collect()
    }

    /// Return a reference to a specific database entry.
    pub fn get_entry(&self, idx: usize) -> &[u8] {
        &self.db[idx]
    }

    /// Stream the entire database (used during the offline phase).
    /// Calls the callback with (index, entry) for each entry.
    pub fn stream_db(&self, mut callback: impl FnMut(usize, &[u8])) {
        for (i, entry) in self.db.iter().enumerate() {
            callback(i, entry);
        }
    }

    /// Number of entries in the database.
    pub fn num_entries(&self) -> usize {
        self.db.len()
    }

    /// Entry size in bytes.
    pub fn entry_size(&self) -> usize {
        self.w
    }

    /// Handle a database modification: return the XOR diff between old and new entry.
    /// The caller is responsible for updating the database.
    pub fn modify_entry(&mut self, idx: usize, new_entry: Vec<u8>) -> Vec<u8> {
        assert!(idx < self.db.len());
        assert_eq!(new_entry.len(), self.w);
        let diff = crate::util::xor_bytes(&self.db[idx], &new_entry);
        self.db[idx] = new_entry;
        diff
    }
}
