package com.bitcoinpir.onionpir;

import com.bitcoinpir.PirConstants;
import com.bitcoinpir.hash.CuckooHash;
import com.bitcoinpir.hash.PirHash;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Client-side cuckoo table reconstruction for OnionPIR chunk-level queries.
 *
 * <p>OnionPIR chunk-level databases use a cuckoo hash table with
 * {@link PirConstants#ONION_CHUNK_CUCKOO_NUM_HASHES} (6) hash functions.
 * The client must reconstruct the cuckoo table for each group to find the
 * exact bin index where a given entry_id is stored.
 *
 * <p>The cuckoo table structure is deterministic: given the same set of
 * entry_ids and hash function keys, both client and server produce the
 * same table layout.
 */
public final class OnionChunkCuckoo {
    private OnionChunkCuckoo() {}

    /**
     * Build a reverse index mapping each chunk group to its assigned entry_ids.
     *
     * @param totalEntries total number of packed entries in the database
     * @return reverseIndex[groupId] = list of entry_ids assigned to that group
     */
    public static List<List<Integer>> buildReverseIndex(int totalEntries) {
        List<List<Integer>> index = new ArrayList<>(PirConstants.K_CHUNK);
        for (int g = 0; g < PirConstants.K_CHUNK; g++) {
            index.add(new ArrayList<>());
        }

        for (int eid = 0; eid < totalEntries; eid++) {
            int[] buckets = PirHash.deriveChunkBuckets(eid);
            for (int g : buckets) {
                index.get(g).add(eid);
            }
        }
        return index;
    }

    /**
     * Build the cuckoo hash table for a specific chunk group.
     *
     * <p>Uses 6 hash functions and deterministic kicking to produce a table
     * layout identical to the server's.
     *
     * @param groupId       the chunk group (0 .. K_CHUNK-1)
     * @param reverseIndex  reverse index from {@link #buildReverseIndex}
     * @param binsPerTable  number of bins in the cuckoo table (chunk_bins from server)
     * @return table[bin] = entry_id (or {@link PirConstants#EMPTY_U32} if empty)
     */
    public static int[] buildCuckooTable(int groupId, List<List<Integer>> reverseIndex, int binsPerTable) {
        List<Integer> entries = reverseIndex.get(groupId);
        int numHashes = PirConstants.ONION_CHUNK_CUCKOO_NUM_HASHES;
        int maxKicks = PirConstants.ONION_CHUNK_CUCKOO_MAX_KICKS;

        // Precompute cuckoo hash function keys for this group
        long[] keys = new long[numHashes];
        for (int h = 0; h < numHashes; h++) {
            keys[h] = CuckooHash.deriveChunkCuckooKey(groupId, h);
        }

        int[] table = new int[binsPerTable];
        java.util.Arrays.fill(table, PirConstants.EMPTY_U32);

        for (int entryId : entries) {
            // Try direct insertion
            boolean placed = false;
            for (int h = 0; h < numHashes; h++) {
                int bin = CuckooHash.cuckooHashInt(entryId, keys[h], binsPerTable);
                if (table[bin] == PirConstants.EMPTY_U32) {
                    table[bin] = entryId;
                    placed = true;
                    break;
                }
            }
            if (placed) continue;

            // Cuckoo kicking
            int currentId = entryId;
            int currentHashFn = 0;
            int currentBin = CuckooHash.cuckooHashInt(entryId, keys[0], binsPerTable);
            boolean success = false;

            for (int kick = 0; kick < maxKicks; kick++) {
                int evicted = table[currentBin];
                table[currentBin] = currentId;

                // Try to place evicted item in an empty slot
                for (int hOff = 0; hOff < numHashes; hOff++) {
                    int tryH = (currentHashFn + 1 + hOff) % numHashes;
                    int bin = CuckooHash.cuckooHashInt(evicted, keys[tryH], binsPerTable);
                    if (bin == currentBin) continue;
                    if (table[bin] == PirConstants.EMPTY_U32) {
                        table[bin] = evicted;
                        success = true;
                        break;
                    }
                }
                if (success) break;

                // Evict to a different bin
                int altH = (currentHashFn + 1 + kick % (numHashes - 1)) % numHashes;
                int altBin = CuckooHash.cuckooHashInt(evicted, keys[altH], binsPerTable);
                if (altBin == currentBin) {
                    int h2 = (altH + 1) % numHashes;
                    altBin = CuckooHash.cuckooHashInt(evicted, keys[h2], binsPerTable);
                }

                currentId = evicted;
                currentHashFn = altH;
                currentBin = altBin;
            }

            if (!success) {
                throw new RuntimeException(
                    "Client cuckoo placement failed for entry_id=" + entryId +
                    " in group=" + groupId);
            }
        }

        return table;
    }

    /**
     * Find which bin holds a given entry_id in a cuckoo table.
     *
     * @param table       the cuckoo table from {@link #buildCuckooTable}
     * @param entryId     the entry to find
     * @param groupId     the group ID (for key derivation)
     * @param binsPerTable number of bins
     * @return the bin index, or -1 if not found
     */
    public static int findEntryBin(int[] table, int entryId, int groupId, int binsPerTable) {
        int numHashes = PirConstants.ONION_CHUNK_CUCKOO_NUM_HASHES;
        for (int h = 0; h < numHashes; h++) {
            long key = CuckooHash.deriveChunkCuckooKey(groupId, h);
            int bin = CuckooHash.cuckooHashInt(entryId, key, binsPerTable);
            if (table[bin] == entryId) {
                return bin;
            }
        }
        return -1;
    }
}
