use pir_sdk::{BucketRef, QueryResult, ScriptHash, UtxoEntry};

/// Opaque result released only by an atomic query + semantic reconstruction +
/// Merkle verification operation.
///
/// Unlike [`QueryResult`], this type is a verification authority: callers
/// cannot construct it, mutate its entries, or deserialize it. The exact
/// script hash and database id are retained alongside the read-only result so
/// consumers do not have to infer the binding from a parallel mutable array.
#[derive(Debug)]
pub struct VerifiedQueryResult {
    script_hash: ScriptHash,
    db_id: u8,
    inner: QueryResult,
}

impl VerifiedQueryResult {
    /// Construct an authority-bearing result after every atomic verification
    /// stage has passed. Kept crate-private so external Rust callers cannot
    /// mint the type from caller-controlled fields.
    pub(crate) fn new(script_hash: ScriptHash, db_id: u8, mut inner: QueryResult) -> Self {
        // The opaque type, not a forgeable bool in the raw data container, is
        // the release authority. Keep even the private payload pessimistic so
        // cloning/demotion cannot accidentally preserve authority.
        inner.merkle_verified = false;
        Self {
            script_hash,
            db_id,
            inner,
        }
    }

    /// Exact HASH160 input whose result was verified.
    pub fn script_hash(&self) -> ScriptHash {
        self.script_hash
    }

    /// Exact database id whose catalog parameters and Merkle root were used.
    pub fn db_id(&self) -> u8 {
        self.db_id
    }

    /// Verified decoded UTXO entries. The slice is immutable so changing data
    /// requires an explicit authority-dropping conversion.
    pub fn entries(&self) -> &[UtxoEntry] {
        &self.inner.entries
    }

    pub fn is_whale(&self) -> bool {
        self.inner.is_whale
    }

    pub fn total_balance(&self) -> u64 {
        self.inner.total_balance()
    }

    pub fn utxo_count(&self) -> usize {
        self.inner.utxo_count()
    }

    pub fn raw_chunk_data(&self) -> Option<&[u8]> {
        self.inner.raw_chunk_data.as_deref()
    }

    pub fn index_bins(&self) -> &[BucketRef] {
        &self.inner.index_bins
    }

    pub fn chunk_bins(&self) -> &[BucketRef] {
        &self.inner.chunk_bins
    }

    pub fn matched_index_idx(&self) -> Option<usize> {
        self.inner.matched_index_idx
    }

    /// Copy the payload into the legacy mutable container while explicitly
    /// dropping verification authority. The returned `merkle_verified` flag
    /// is always false, including after callers mutate its entries.
    pub fn to_unverified_query_result(&self) -> QueryResult {
        let mut result = self.inner.clone();
        result.merkle_verified = false;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_requires_authority_demotion_and_cannot_change_verified_data() {
        let mut raw = QueryResult::with_entries(vec![UtxoEntry {
            txid: [0x42; 32],
            vout: 3,
            amount_sats: 21,
        }]);
        raw.merkle_verified = true;
        let verified = VerifiedQueryResult::new([0x11; 20], 7, raw);

        let mut demoted = verified.to_unverified_query_result();
        demoted.entries[0].amount_sats = 999;
        demoted.merkle_verified = true; // forgeable legacy metadata

        assert_eq!(verified.entries()[0].amount_sats, 21);
        assert_eq!(verified.script_hash(), [0x11; 20]);
        assert_eq!(verified.db_id(), 7);
        assert_eq!(demoted.entries[0].amount_sats, 999);
        assert!(demoted.merkle_verified);

        let demoted_again = verified.to_unverified_query_result();
        assert!(!demoted_again.merkle_verified);
    }
}
