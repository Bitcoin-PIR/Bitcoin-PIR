package com.bitcoinpir.harmony;

import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;
import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.hash.CuckooHash;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.net.PirWebSocket;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

/**
 * Diagnostic test to trace HarmonyPIR parameter flow and identify
 * where the query fails to find matching tags.
 */
class HarmonyDiagnosticTest {

    static final String HINT_SERVER = "ws://localhost:8094";
    static final String QUERY_SERVER = "ws://localhost:8095";

    // 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 — DPF found 62 UTXOs for this
    static final String TEST_SPK = "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac";

    @Test
    void diagnoseHarmonyParameters() throws Exception {
        byte[] spk = PirHash.hexToBytes(TEST_SPK);
        byte[] scriptHash = PirHash.hash160(spk);
        System.out.println("scriptHash = " + PirHash.bytesToHex(scriptHash));

        // ── Step 1: Get server info ──────────────────────────────────────
        int indexBins, chunkBins;
        long tagSeed;
        try (var ws = new PirWebSocket(QUERY_SERVER)) {
            ws.connect();
            byte[] infoPayload = ws.sendSync(ProtocolCodec.encodeHarmonyGetInfo());
            var info = ProtocolCodec.decodeServerInfo(infoPayload);
            indexBins = info.indexBins();
            chunkBins = info.chunkBins();
            tagSeed = info.tagSeed();
            System.out.printf("Query server: indexBins=%d chunkBins=%d indexK=%d chunkK=%d tagSeed=0x%016x%n",
                    indexBins, chunkBins, info.indexK(), info.chunkK(), tagSeed);
        }

        // ── Step 2: Derive PBC buckets for the test address ──────────────
        int[] candidateBuckets = PirHash.deriveBuckets(scriptHash);
        System.out.printf("PBC candidate buckets: [%d, %d, %d]%n",
                candidateBuckets[0], candidateBuckets[1], candidateBuckets[2]);

        long expectedTag = PirHash.computeTag(tagSeed, scriptHash);
        System.out.printf("Expected tag: 0x%016x%n", expectedTag);

        // For bucket 0 candidate, compute cuckoo bin indices
        int testBucket = candidateBuckets[0];
        for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
            long ck = CuckooHash.deriveCuckooKey(testBucket, h);
            int binIndex = CuckooHash.cuckooHash(scriptHash, ck, indexBins);
            System.out.printf("  bucket=%d hash_fn=%d → cuckoo_key=0x%016x → binIndex=%d (of %d)%n",
                    testBucket, h, ck, binIndex, indexBins);
        }

        // ── Step 3: Download hint for the test bucket ────────────────────
        byte[] prpKey = new byte[16];
        new SecureRandom().nextBytes(prpKey);
        int serverPrp = PirConstants.SERVER_PRP_ALF;

        ProtocolCodec.HintData hint;
        try (var hintWs = new PirWebSocket(HINT_SERVER)) {
            hintWs.connect();
            byte[] hintReq = ProtocolCodec.encodeHarmonyHintRequest(
                    prpKey, serverPrp, 0, new int[]{testBucket});
            var futures = hintWs.sendExpectingN(hintReq, 1);
            hint = ProtocolCodec.decodeHarmonyHintResponse(futures.get(0).get());
        }

        System.out.printf("Hint for bucket %d: n=%d t=%d m=%d hintBytes=%d%n",
                hint.bucketId(), hint.n(), hint.t(), hint.m(), hint.hintBytes().length);
        System.out.printf("  indexBins (from query server) = %d%n", indexBins);
        System.out.printf("  hint.n() (from hint server)   = %d%n", hint.n());
        System.out.printf("  MATCH? %s%n", (indexBins == hint.n()) ? "YES" : "NO ← POTENTIAL ISSUE");

        // ── Step 4: Create bucket and do a round-trip query ──────────────
        if (!HarmonyBucket.isNativeLoaded()) {
            System.out.println("SKIP: harmonypir_jni not loaded");
            return;
        }

        try (var bucket = new HarmonyBucket(
                hint.n(), PirConstants.HARMONY_INDEX_W, hint.t(),
                prpKey, testBucket, HarmonyBucket.PRP_ALF)) {

            bucket.loadHints(hint.hintBytes());
            System.out.printf("Bucket created: n=%d t=%d m=%d w=%d maxQ=%d%n",
                    bucket.getN(), bucket.getT(), bucket.getM(), bucket.getW(),
                    bucket.getMaxQueries());

            // Query for each hash function
            try (var queryWs = new PirWebSocket(QUERY_SERVER)) {
                queryWs.connect();

                for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
                    long ck = CuckooHash.deriveCuckooKey(testBucket, h);
                    int binIndex = CuckooHash.cuckooHash(scriptHash, ck, indexBins);

                    System.out.printf("%n── Query hash_fn=%d binIndex=%d ──%n", h, binIndex);

                    // Check if binIndex is within the bucket's n
                    if (binIndex >= bucket.getN()) {
                        System.out.printf("  WARNING: binIndex=%d >= bucket.n=%d!%n",
                                binIndex, bucket.getN());
                    }

                    byte[] request = bucket.buildRequest(binIndex);
                    int reqIndices = request.length / 4;
                    System.out.printf("  Request: %d indices (%d bytes)%n", reqIndices, request.length);

                    // Send single-bucket batch query
                    byte[] batchMsg = ProtocolCodec.encodeHarmonyBatchQuery(
                            0, h, 1, new int[]{testBucket}, new byte[][]{request});
                    byte[] batchResp = queryWs.sendSync(batchMsg);

                    var result = ProtocolCodec.decodeHarmonyBatchResult(batchResp);
                    byte[] respData = result.items()[0].subResults()[0];
                    System.out.printf("  Response: %d bytes (expected %d = %d indices × %d)%n",
                            respData.length, reqIndices * PirConstants.HARMONY_INDEX_W,
                            reqIndices, PirConstants.HARMONY_INDEX_W);

                    // Process response
                    byte[] entry = bucket.processResponse(respData);
                    System.out.printf("  Recovered entry: %d bytes%n", entry.length);

                    // Dump the 3 slots
                    for (int slot = 0; slot < PirConstants.CUCKOO_BUCKET_SIZE; slot++) {
                        int base = slot * PirConstants.INDEX_ENTRY_SIZE;
                        if (base + PirConstants.INDEX_ENTRY_SIZE > entry.length) break;
                        ByteBuffer bb = ByteBuffer.wrap(entry, base, PirConstants.INDEX_ENTRY_SIZE)
                                .order(ByteOrder.LITTLE_ENDIAN);
                        long slotTag = bb.getLong();
                        int startChunk = bb.getInt();
                        int numChunks = entry[base + 12] & 0xFF;
                        boolean isMatch = (slotTag == expectedTag);
                        System.out.printf("  Slot %d: tag=0x%016x startChunk=%d numChunks=%d %s%n",
                                slot, slotTag, startChunk, numChunks,
                                isMatch ? "← MATCH!" : (slotTag == 0 ? "(empty)" : ""));
                    }

                    int[] found = UtxoDecoder.findEntryInIndexResult(entry, expectedTag);
                    if (found != null) {
                        System.out.printf("  FOUND: startChunkId=%d numChunks=%d%n", found[0], found[1]);
                    } else {
                        System.out.println("  NOT FOUND in this bin");
                    }
                }
            }
        }
    }
}
