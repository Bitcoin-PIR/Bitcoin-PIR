package com.bitcoinpir.onionpir;

import com.bitcoinpir.PirClient;
import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;
import com.bitcoinpir.codec.ProtocolCodec.OnionPirServerInfo;
import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.hash.CuckooHash;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.net.PirWebSocket;
import com.bitcoinpir.placement.PbcPlanner;

import java.util.*;
import java.util.logging.Logger;

/**
 * OnionPIRv2 single-server FHE-based PIR client.
 *
 * <p>Uses the {@code com.onionpir.jna} JNA binding for FHE operations:
 * key generation, query encryption, and response decryption.
 *
 * <p>Build the native library:
 * <pre>
 *   cd OnionPIRv2
 *   mkdir build-shared && cd build-shared
 *   cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
 *   make -j$(nproc)
 * </pre>
 *
 * <p>Privacy model: single server, computational privacy via lattice-based FHE.
 * No trust assumptions between servers, but significantly slower queries.
 *
 * <h3>Query flow</h3>
 * <ol>
 *   <li>Key registration: generate FHE keys, send to server (once per session)</li>
 *   <li>Index PIR: derive PBC placement, generate FHE queries for each group,
 *       decrypt responses, scan for matching tags</li>
 *   <li>Chunk PIR: collect unique entry_ids, reconstruct cuckoo tables,
 *       generate FHE queries, decrypt packed entries</li>
 *   <li>Reassemble: concatenate packed entries, decode UTXO data</li>
 * </ol>
 */
public class OnionPirClient implements PirClient {
    private static final Logger log = Logger.getLogger(OnionPirClient.class.getName());

    private final String serverUrl;

    private PirWebSocket ws;
    private boolean connected;

    // Server parameters (from OnionPIR v2 GetInfo)
    private int indexK;
    private int chunkK;
    private int indexBins;
    private int chunkBins;
    private long tagSeed;
    private int totalPackedEntries;
    private int indexCuckooBucketSize;
    private int indexSlotSize;

    // FHE clients (shared secret key, per-level database size)
    private com.onionpir.jna.OnionPirClient indexFhe;
    private com.onionpir.jna.OnionPirClient chunkFhe;
    private long clientId;

    // Chunk cuckoo cache (lazily built)
    private List<List<Integer>> reverseIndex;
    private final Map<Integer, int[]> cuckooCache = new HashMap<>();

    // RNG state for dummy queries
    private long rngState = System.nanoTime();

    public OnionPirClient(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    @Override
    public void connect() throws Exception {
        checkNativeLibrary();

        ws = new PirWebSocket(serverUrl);
        ws.connect();

        // Fetch OnionPIR v2 server info
        byte[] infoPayload = ws.sendSync(ProtocolCodec.encodeGetInfo());
        OnionPirServerInfo info = ProtocolCodec.decodeOnionPirServerInfo(infoPayload);
        indexK = info.indexK();
        chunkK = info.chunkK();
        indexBins = info.indexBins();
        chunkBins = info.chunkBins();
        tagSeed = info.tagSeed();
        totalPackedEntries = info.totalPackedEntries();
        indexCuckooBucketSize = info.indexCuckooBucketSize();
        indexSlotSize = info.indexSlotSize();

        log.info("OnionPIR info: indexK=" + indexK + " chunkK=" + chunkK +
                " indexBins=" + indexBins + " chunkBins=" + chunkBins +
                " totalPacked=" + totalPackedEntries);

        // Initialize FHE keys and register with server
        registerKeys();

        connected = true;
        log.info("OnionPIR connected and keys registered");
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public Map<Integer, List<UtxoDecoder.UtxoEntry>> queryBatch(List<byte[]> scriptHashes) throws Exception {
        if (scriptHashes.isEmpty()) return Map.of();

        int N = scriptHashes.size();

        // Precompute tags for all queries
        long[] tags = new long[N];
        for (int i = 0; i < N; i++) {
            tags[i] = PirHash.computeTag(tagSeed, scriptHashes.get(i));
        }

        // ── Level 1: Index PIR ──────────────────────────────────────────────

        // Derive PBC candidate groups for each query
        int[][] itemBuckets = new int[N][];
        for (int i = 0; i < N; i++) {
            itemBuckets[i] = PirHash.deriveBuckets(scriptHashes.get(i));
        }

        // Plan rounds via PBC cuckoo placement
        List<int[][]> rounds = PbcPlanner.planRounds(itemBuckets, indexK);

        // IndexResult: queryIndex -> {entryId, byteOffset, numEntries}
        Map<Integer, int[]> indexResults = new HashMap<>();
        int totalRounds = 0;

        for (int[][] round : rounds) {
            // Build group -> queryIndex mapping for this round
            Map<Integer, Integer> groupToQuery = new HashMap<>();
            for (int[] entry : round) {
                groupToQuery.put(entry[1], entry[0]); // group -> queryIndex
            }

            // Generate indexK * INDEX_CUCKOO_NUM_HASHES FHE queries
            int numQueries = indexK * PirConstants.INDEX_CUCKOO_NUM_HASHES;
            byte[][] queries = new byte[numQueries][];
            int[] queryBins = new int[numQueries];

            for (int g = 0; g < indexK; g++) {
                for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
                    int qi = g * PirConstants.INDEX_CUCKOO_NUM_HASHES + h;
                    int binIdx;

                    Integer queryIdx = groupToQuery.get(g);
                    if (queryIdx != null && !indexResults.containsKey(queryIdx)) {
                        // Real query — compute cuckoo bin index
                        long ck = CuckooHash.deriveCuckooKey(g, h);
                        binIdx = CuckooHash.cuckooHash(scriptHashes.get(queryIdx), ck, indexBins);
                    } else {
                        // Dummy — random bin
                        binIdx = nextDummyBin(indexBins);
                    }

                    queries[qi] = indexFhe.generateQuery(binIdx);
                    queryBins[qi] = binIdx;
                }
            }

            // Send batch to server
            byte[] batchMsg = ProtocolCodec.encodeOnionPirQuery(
                    PirConstants.REQ_ONIONPIR_INDEX_QUERY, totalRounds, queries);
            byte[] batchResp = ws.sendSync(batchMsg);
            byte[][] results = ProtocolCodec.decodeOnionPirResult(batchResp);
            totalRounds++;

            // Decrypt and scan for matching tags
            for (int[] entry : round) {
                int queryIdx = entry[0];
                int group = entry[1];

                if (indexResults.containsKey(queryIdx)) continue;

                for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
                    int qi = group * PirConstants.INDEX_CUCKOO_NUM_HASHES + h;
                    byte[] decrypted = indexFhe.decryptResponse(queryBins[qi], results[qi]);

                    int[] found = scanOnionIndexBin(decrypted, tags[queryIdx]);
                    if (found != null) {
                        indexResults.put(queryIdx, found);
                        break;
                    }
                }
            }
        }

        log.info("Level 1: " + indexResults.size() + "/" + N + " found");

        // ── Level 2: Chunk PIR ──────────────────────────────────────────────

        // Collect unique entry_ids from index results
        List<Integer> uniqueEntryIds = new ArrayList<>();
        Map<Integer, Integer> entryIdToLocalIdx = new LinkedHashMap<>();

        for (var e : indexResults.entrySet()) {
            int[] ir = e.getValue();
            int entryId = ir[0];
            int numEntries = ir[2];
            if (numEntries == 0) continue; // whale

            for (int i = 0; i < numEntries; i++) {
                int eid = entryId + i;
                if (!entryIdToLocalIdx.containsKey(eid)) {
                    entryIdToLocalIdx.put(eid, uniqueEntryIds.size());
                    uniqueEntryIds.add(eid);
                }
            }
        }

        Map<Integer, byte[]> decryptedEntries = new HashMap<>();

        if (!uniqueEntryIds.isEmpty()) {
            // Build reverse index (lazy, once per session)
            if (reverseIndex == null) {
                log.info("Building chunk reverse index (" + totalPackedEntries + " entries)...");
                long t0 = System.currentTimeMillis();
                reverseIndex = OnionChunkCuckoo.buildReverseIndex(totalPackedEntries);
                log.info("Reverse index built in " + (System.currentTimeMillis() - t0) + " ms");
            }

            // PBC placement of entry_ids into chunk groups
            int[][] entryGroups = new int[uniqueEntryIds.size()][];
            for (int i = 0; i < uniqueEntryIds.size(); i++) {
                entryGroups[i] = PirHash.deriveChunkBuckets(uniqueEntryIds.get(i));
            }

            List<int[][]> chunkRounds = PbcPlanner.planRounds(entryGroups, chunkK);
            log.info("Level 2: " + uniqueEntryIds.size() + " entries -> " + chunkRounds.size() + " round(s)");

            for (int ri = 0; ri < chunkRounds.size(); ri++) {
                int[][] cRound = chunkRounds.get(ri);

                // For each real entry in this round, find its bin in the cuckoo table
                Map<Integer, int[]> groupToEntryInfo = new HashMap<>(); // group -> {entryId, binIdx}
                List<int[]> chunkQueriesInfo = new ArrayList<>(); // {entryId, group, binIdx}

                for (int[] entry : cRound) {
                    int localIdx = entry[0];
                    int group = entry[1];
                    int eid = uniqueEntryIds.get(localIdx);

                    // Build cuckoo table for this group if not cached
                    int[] table = cuckooCache.computeIfAbsent(group,
                            g -> OnionChunkCuckoo.buildCuckooTable(g, reverseIndex, chunkBins));

                    int binIdx = OnionChunkCuckoo.findEntryBin(table, eid, group, chunkBins);
                    if (binIdx < 0) {
                        log.warning("entry_id " + eid + " not found in cuckoo table for group " + group);
                        continue;
                    }

                    groupToEntryInfo.put(group, new int[]{eid, binIdx});
                    chunkQueriesInfo.add(new int[]{eid, group, binIdx});
                }

                // Generate chunkK FHE queries (one per group)
                byte[][] chunkQueries = new byte[chunkK][];
                for (int g = 0; g < chunkK; g++) {
                    int binIdx;
                    int[] info = groupToEntryInfo.get(g);
                    if (info != null) {
                        binIdx = info[1];
                    } else {
                        binIdx = nextDummyBin(chunkBins);
                    }
                    chunkQueries[g] = chunkFhe.generateQuery(binIdx);
                }

                // Send batch to server
                byte[] chunkMsg = ProtocolCodec.encodeOnionPirQuery(
                        PirConstants.REQ_ONIONPIR_CHUNK_QUERY, ri, chunkQueries);
                byte[] chunkResp = ws.sendSync(chunkMsg);
                byte[][] chunkResults = ProtocolCodec.decodeOnionPirResult(chunkResp);

                // Decrypt real entries
                for (int[] cqi : chunkQueriesInfo) {
                    int eid = cqi[0];
                    int group = cqi[1];
                    int binIdx = cqi[2];

                    byte[] decrypted = chunkFhe.decryptResponse(binIdx, chunkResults[group]);
                    // Trim to packed entry size
                    byte[] packed = new byte[PirConstants.ONION_PACKED_ENTRY_SIZE];
                    System.arraycopy(decrypted, 0, packed, 0,
                            Math.min(decrypted.length, PirConstants.ONION_PACKED_ENTRY_SIZE));
                    decryptedEntries.put(eid, packed);
                }
            }

            log.info("Level 2: " + decryptedEntries.size() + "/" + uniqueEntryIds.size() + " entries recovered");
        }

        // ── Reassemble results ──────────────────────────────────────────────

        Map<Integer, List<UtxoDecoder.UtxoEntry>> results = new HashMap<>();

        for (int qi = 0; qi < N; qi++) {
            int[] ir = indexResults.get(qi);
            if (ir == null || ir[2] == 0) {
                // Not found or whale
                results.put(qi, List.of());
                continue;
            }

            int entryId = ir[0];
            int byteOffset = ir[1];
            int numEntries = ir[2];

            // Assemble data from consecutive packed entries
            byte[] fullData = assembleEntryData(decryptedEntries, entryId, byteOffset, numEntries);
            if (fullData.length == 0) {
                results.put(qi, List.of());
                continue;
            }

            UtxoDecoder.DecodeResult dr = UtxoDecoder.decode(fullData);
            results.put(qi, dr.entries());
        }

        return results;
    }

    @Override
    public void close() {
        connected = false;
        if (ws != null) ws.close();
        if (indexFhe != null) { indexFhe.close(); indexFhe = null; }
        if (chunkFhe != null) { chunkFhe.close(); chunkFhe = null; }
        reverseIndex = null;
        cuckooCache.clear();
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /**
     * Initialize FHE keys and register with the server.
     *
     * <p>Creates a keygen client to generate Galois and GSW keys, then creates
     * per-level clients (index and chunk) sharing the same secret key.
     */
    private void registerKeys() throws Exception {
        log.info("Generating FHE keys...");
        long t0 = System.currentTimeMillis();

        // Create keygen client (num_entries=0 for key generation)
        try (com.onionpir.jna.OnionPirClient keygen = new com.onionpir.jna.OnionPirClient(0)) {
            clientId = keygen.getId();
            byte[] galoisKeys = keygen.generateGaloisKeys();
            byte[] gswKeys = keygen.generateGswKeys();
            byte[] secretKey = keygen.exportSecretKey();

            // Create per-level clients from the same secret key
            indexFhe = com.onionpir.jna.OnionPirClient.fromSecretKey(indexBins, clientId, secretKey);
            chunkFhe = com.onionpir.jna.OnionPirClient.fromSecretKey(chunkBins, clientId, secretKey);

            // Send keys to server
            byte[] regMsg = ProtocolCodec.encodeOnionPirRegisterKeys(galoisKeys, gswKeys);
            byte[] ack = ws.sendSync(regMsg);
            if (ack[0] != PirConstants.RESP_KEYS_ACK) {
                throw new RuntimeException("Key registration failed: 0x" +
                        Integer.toHexString(ack[0] & 0xFF));
            }
        }

        long elapsed = System.currentTimeMillis() - t0;
        log.info("FHE keys registered in " + elapsed + " ms");
    }

    /**
     * Scan a decrypted OnionPIR index bin for a matching tag.
     *
     * <p>OnionPIR index slot format: [8B tag][4B entry_id][2B byte_offset][1B num_entries]
     *
     * @return int[3] = {entryId, byteOffset, numEntries}, or null if not found
     */
    private int[] scanOnionIndexBin(byte[] entryBytes, long expectedTag) {
        for (int slot = 0; slot < indexCuckooBucketSize; slot++) {
            int off = slot * indexSlotSize;
            if (off + indexSlotSize > entryBytes.length) break;

            long slotTag = readLongLE(entryBytes, off);
            if (slotTag == expectedTag && slotTag != 0) {
                int entryId = readIntLE(entryBytes, off + 8);
                int byteOffset = readShortLE(entryBytes, off + 12);
                int numEntries = entryBytes[off + 14] & 0xFF;
                return new int[]{entryId, byteOffset, numEntries};
            }
        }
        return null;
    }

    /**
     * Assemble UTXO data from consecutive packed entries.
     *
     * <p>For the first entry, data starts at byteOffset. For subsequent entries,
     * use the full entry from offset 0.
     */
    private static byte[] assembleEntryData(
            Map<Integer, byte[]> decryptedEntries,
            int entryId, int byteOffset, int numEntries) {

        int totalSize = 0;
        for (int i = 0; i < numEntries; i++) {
            byte[] entry = decryptedEntries.get(entryId + i);
            if (entry == null) break;
            totalSize += (i == 0) ? (entry.length - byteOffset) : entry.length;
        }
        if (totalSize == 0) return new byte[0];

        byte[] fullData = new byte[totalSize];
        int pos = 0;
        for (int i = 0; i < numEntries; i++) {
            byte[] entry = decryptedEntries.get(entryId + i);
            if (entry == null) break;

            int srcOff = (i == 0) ? byteOffset : 0;
            int len = entry.length - srcOff;
            System.arraycopy(entry, srcOff, fullData, pos, len);
            pos += len;
        }

        return fullData;
    }

    /** Generate a deterministic pseudo-random dummy bin index. */
    private int nextDummyBin(int numBins) {
        rngState = (rngState + 0x9e3779b97f4a7c15L);
        long h = PirHash.splitmix64(rngState);
        return (int) Long.remainderUnsigned(h, numBins);
    }

    /** Read a little-endian long from a byte array. */
    private static long readLongLE(byte[] data, int off) {
        return (data[off] & 0xFFL)
             | ((data[off + 1] & 0xFFL) << 8)
             | ((data[off + 2] & 0xFFL) << 16)
             | ((data[off + 3] & 0xFFL) << 24)
             | ((data[off + 4] & 0xFFL) << 32)
             | ((data[off + 5] & 0xFFL) << 40)
             | ((data[off + 6] & 0xFFL) << 48)
             | ((data[off + 7] & 0xFFL) << 56);
    }

    /** Read a little-endian int from a byte array. */
    private static int readIntLE(byte[] data, int off) {
        return (data[off] & 0xFF)
             | ((data[off + 1] & 0xFF) << 8)
             | ((data[off + 2] & 0xFF) << 16)
             | ((data[off + 3] & 0xFF) << 24);
    }

    /** Read a little-endian unsigned short from a byte array. */
    private static int readShortLE(byte[] data, int off) {
        return (data[off] & 0xFF) | ((data[off + 1] & 0xFF) << 8);
    }

    private void checkNativeLibrary() {
        try {
            // Verify JNA can load the OnionPIR shared library
            Class.forName("com.onionpir.jna.OnionPirLibrary");
        } catch (ClassNotFoundException e) {
            throw new UnsatisfiedLinkError(
                "OnionPIR JNA classes not found on classpath");
        }
    }
}
