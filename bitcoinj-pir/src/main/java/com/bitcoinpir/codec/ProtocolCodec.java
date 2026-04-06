package com.bitcoinpir.codec;

import com.bitcoinpir.PirConstants;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Binary message encoding/decoding for the PIR WebSocket protocol.
 * All messages: [4B length LE][1B variant][payload...]
 */
public final class ProtocolCodec {
    private ProtocolCodec() {}

    // ── Message framing ─────────────────────────────────────────────────────

    /** Wrap a payload (variant + data) in a length-prefixed message. */
    public static byte[] frame(byte[] payload) {
        byte[] msg = new byte[4 + payload.length];
        ByteBuffer.wrap(msg, 0, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(payload.length);
        System.arraycopy(payload, 0, msg, 4, payload.length);
        return msg;
    }

    /** Extract the variant byte from a raw message (after removing length prefix). */
    public static byte variant(byte[] payload) {
        return payload[0];
    }

    // ── GetInfo ──────────────────────────────────────────────────────────────

    /** Encode a GetInfo request. */
    public static byte[] encodeGetInfo() {
        return frame(new byte[]{PirConstants.REQ_GET_INFO});
    }

    /** Encode a HarmonyPIR GetInfo request. */
    public static byte[] encodeHarmonyGetInfo() {
        return frame(new byte[]{PirConstants.REQ_HARMONY_GET_INFO});
    }

    /** Parsed server info response. */
    public record ServerInfo(int indexBins, int chunkBins, int indexK, int chunkK, long tagSeed) {}

    /** Decode a ServerInfo response payload (after length prefix). */
    public static ServerInfo decodeServerInfo(byte[] payload) {
        // payload[0] = variant (0x01 or 0x40)
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int indexBins = bb.getInt();
        int chunkBins = bb.getInt();
        int indexK = bb.get() & 0xFF;
        int chunkK = bb.get() & 0xFF;
        long tagSeed = bb.getLong();
        return new ServerInfo(indexBins, chunkBins, indexK, chunkK, tagSeed);
    }

    // ── OnionPIR GetInfo ───────────────────────────────────────────────────

    /** Parsed OnionPIR server info response (v2 format with additional fields). */
    public record OnionPirServerInfo(
        int indexK, int chunkK,
        int indexBins, int chunkBins,
        long tagSeed,
        int totalPackedEntries,
        int indexCuckooBucketSize,
        int indexSlotSize
    ) {}

    /**
     * Decode an OnionPIR v2 ServerInfo response payload.
     *
     * Wire format (after length prefix):
     *   [1B variant=0x01][1B index_k][1B chunk_k][4B index_bins LE][4B chunk_bins LE]
     *   [8B tag_seed LE][4B total_packed LE][2B slots_per_bin LE][1B slot_size]
     */
    public static OnionPirServerInfo decodeOnionPirServerInfo(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int indexK = bb.get() & 0xFF;
        int chunkK = bb.get() & 0xFF;
        int indexBins = bb.getInt();
        int chunkBins = bb.getInt();
        long tagSeed = bb.getLong();
        int totalPackedEntries = bb.getInt();
        int indexCuckooBucketSize = bb.getShort() & 0xFFFF;
        int indexSlotSize = bb.get() & 0xFF;
        return new OnionPirServerInfo(indexK, chunkK, indexBins, chunkBins, tagSeed,
                totalPackedEntries, indexCuckooBucketSize, indexSlotSize);
    }

    // ── Ping ─────────────────────────────────────────────────────────────────

    /** Encode a Ping request. */
    public static byte[] encodePing() {
        return frame(new byte[]{PirConstants.REQ_PING});
    }

    /** Check if a payload is a Pong response. */
    public static boolean isPong(byte[] payload) {
        return payload.length == 1 && payload[0] == PirConstants.RESP_PONG;
    }

    // ── DPF Batch ────────────────────────────────────────────────────────────

    /**
     * Encode an IndexBatch or ChunkBatch request.
     *
     * @param variant  REQ_INDEX_BATCH (0x11) or REQ_CHUNK_BATCH (0x21)
     * @param roundId  round identifier
     * @param keys     keys[group][keyIndex] = DPF key bytes
     */
    public static byte[] encodeBatchRequest(byte variant, int roundId, byte[][][] keys) {
        int numGroups = keys.length;
        int keysPerGroup = keys[0].length;

        // Calculate total size
        int payloadSize = 1 + 2 + 1 + 1; // variant + roundId + numGroups + keysPerGroup
        for (byte[][] groupKeys : keys) {
            for (byte[] key : groupKeys) {
                payloadSize += 2 + key.length; // keyLen + keyData
            }
        }

        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(variant);
        bb.putShort((short) roundId);
        bb.put((byte) numGroups);
        bb.put((byte) keysPerGroup);

        for (byte[][] groupKeys : keys) {
            for (byte[] key : groupKeys) {
                bb.putShort((short) key.length);
                bb.put(key);
            }
        }

        return frame(payload);
    }

    /** Parsed batch result: results[group][resultIndex] = result bytes. */
    public record BatchResult(int roundId, byte[][][] results) {}

    /** Decode a BatchResult response payload. */
    public static BatchResult decodeBatchResult(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int roundId = bb.getShort() & 0xFFFF;
        int numGroups = bb.get() & 0xFF;
        int resultsPerGroup = bb.get() & 0xFF;

        byte[][][] results = new byte[numGroups][resultsPerGroup][];
        for (int b = 0; b < numGroups; b++) {
            for (int r = 0; r < resultsPerGroup; r++) {
                int len = bb.getShort() & 0xFFFF;
                byte[] data = new byte[len];
                bb.get(data);
                results[b][r] = data;
            }
        }
        return new BatchResult(roundId, results);
    }

    // ── HarmonyPIR Hint Request ─────────────────────────────────────────────

    /**
     * Encode a HarmonyPIR hint request.
     *
     * Wire: [0x41][16B prpKey][1B prpBackend][1B level][1B numGroups][per group: 1B id]
     *
     * @param prpKey     16-byte master PRP key
     * @param prpBackend server-side PRP backend constant (0=Hoang, 1=FastPRP, 2=ALF)
     * @param level      0 = index, 1 = chunk
     * @param groupIds  which groups to generate hints for
     */
    public static byte[] encodeHarmonyHintRequest(byte[] prpKey, int prpBackend,
            int level, int[] groupIds) {
        int payloadSize = 1 + 16 + 1 + 1 + 1 + groupIds.length;
        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PirConstants.REQ_HARMONY_HINTS);
        bb.put(prpKey);
        bb.put((byte) prpBackend);
        bb.put((byte) level);
        bb.put((byte) groupIds.length);
        for (int id : groupIds) bb.put((byte) id);
        return frame(payload);
    }

    /** Parsed hint response from the hint server. */
    public record HintData(int groupId, int n, int t, int m, byte[] hintBytes) {}

    /**
     * Decode a HarmonyPIR hint response payload.
     *
     * Wire: [0x41][1B groupId][4B n LE][4B t LE][4B m LE][flat hints...]
     */
    public static HintData decodeHarmonyHintResponse(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int groupId = bb.get() & 0xFF;
        int n = bb.getInt();
        int t = bb.getInt();
        int m = bb.getInt();
        byte[] hints = new byte[payload.length - 14];
        System.arraycopy(payload, 14, hints, 0, hints.length);
        return new HintData(groupId, n, t, m, hints);
    }

    // ── HarmonyPIR Batch Query ──────────────────────────────────────────────

    /**
     * Encode a HarmonyPIR batch query request.
     *
     * Wire format:
     *   [0x43][1B level][2B roundId LE][2B numGroups LE][1B subQueriesPerGroup]
     *   per group:
     *     [1B groupId]
     *     per sub-query:
     *       [4B count LE]             (number of u32 indices)
     *       [count × 4B u32 LE]       (sorted indices from buildRequest)
     *
     * @param level              0 = index, 1 = chunk
     * @param roundId            round identifier
     * @param subQueriesPerGroup number of sub-queries per group (always 1)
     * @param groupIds           group identifiers
     * @param requests           requests[i] = raw request bytes for group groupIds[i]
     *                           (sequence of 4-byte LE u32 from buildRequest)
     */
    public static byte[] encodeHarmonyBatchQuery(int level, int roundId,
            int subQueriesPerGroup, int[] groupIds, byte[][] requests) {
        // Calculate size
        int payloadSize = 1 + 1 + 2 + 2 + 1; // variant + level + roundId + numGroups + subQPerGroup
        for (byte[] req : requests) {
            payloadSize += 1 + 4 + req.length; // groupId + count(u32) + data
        }

        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PirConstants.REQ_HARMONY_BATCH_QUERY);
        bb.put((byte) level);
        bb.putShort((short) roundId);
        bb.putShort((short) groupIds.length);
        bb.put((byte) subQueriesPerGroup);

        for (int i = 0; i < groupIds.length; i++) {
            bb.put((byte) groupIds[i]);
            int indexCount = requests[i].length / 4; // number of u32 indices
            bb.putInt(indexCount);
            bb.put(requests[i]);
        }

        return frame(payload);
    }

    /** Parsed HarmonyPIR batch result item. */
    public record HarmonyBatchResultItem(int groupId, byte[][] subResults) {}

    /** Parsed HarmonyPIR batch result. */
    public record HarmonyBatchResult(int level, int roundId, HarmonyBatchResultItem[] items) {}

    /**
     * Decode a HarmonyPIR batch query response.
     *
     * Wire format (after length prefix):
     *   [0x43][1B level][2B roundId LE][2B numGroups LE][1B subResultsPerGroup]
     *   per group:
     *     [1B groupId]
     *     per sub-result:
     *       [4B dataLen LE]
     *       [dataLen bytes]
     */
    public static HarmonyBatchResult decodeHarmonyBatchResult(byte[] payload) {
        int level = payload[1] & 0xFF;
        int roundId = ByteBuffer.wrap(payload, 2, 2).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int numGroups = ByteBuffer.wrap(payload, 4, 2).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int subResultsPerGroup = payload[6] & 0xFF;

        int pos = 7;
        HarmonyBatchResultItem[] items = new HarmonyBatchResultItem[numGroups];
        for (int b = 0; b < numGroups; b++) {
            int groupId = payload[pos] & 0xFF;
            pos++;
            byte[][] subResults = new byte[subResultsPerGroup][];
            for (int sr = 0; sr < subResultsPerGroup; sr++) {
                int dataLen = ByteBuffer.wrap(payload, pos, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                pos += 4;
                subResults[sr] = new byte[dataLen];
                System.arraycopy(payload, pos, subResults[sr], 0, dataLen);
                pos += dataLen;
            }
            items[b] = new HarmonyBatchResultItem(groupId, subResults);
        }
        return new HarmonyBatchResult(level, roundId, items);
    }

    // ── OnionPIR ────────────────────────────────────────────────────────────

    /**
     * Encode an OnionPIR key registration request.
     */
    public static byte[] encodeOnionPirRegisterKeys(byte[] galoisKeys, byte[] gswKeys) {
        int payloadSize = 1 + 4 + galoisKeys.length + 4 + gswKeys.length;
        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PirConstants.REQ_REGISTER_KEYS);
        bb.putInt(galoisKeys.length);
        bb.put(galoisKeys);
        bb.putInt(gswKeys.length);
        bb.put(gswKeys);
        return frame(payload);
    }

    /**
     * Encode an OnionPIR index or chunk query request.
     *
     * @param variant  REQ_ONIONPIR_INDEX_QUERY or REQ_ONIONPIR_CHUNK_QUERY
     * @param roundId  round identifier
     * @param queries  FHE-encrypted queries
     */
    public static byte[] encodeOnionPirQuery(byte variant, int roundId, byte[][] queries) {
        int payloadSize = 1 + 2 + 1; // variant + roundId + numQueries
        for (byte[] q : queries) {
            payloadSize += 4 + q.length;
        }

        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(variant);
        bb.putShort((short) roundId);
        bb.put((byte) queries.length);
        for (byte[] q : queries) {
            bb.putInt(q.length);
            bb.put(q);
        }
        return frame(payload);
    }

    /** Decode an OnionPIR query result. */
    public static byte[][] decodeOnionPirResult(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int roundId = bb.getShort() & 0xFFFF;
        int numResults = bb.get() & 0xFF;
        byte[][] results = new byte[numResults][];
        for (int i = 0; i < numResults; i++) {
            int len = bb.getInt();
            results[i] = new byte[len];
            bb.get(results[i]);
        }
        return results;
    }

    // ── Error ────────────────────────────────────────────────────────────────

    /** Decode an error message from payload. */
    public static String decodeError(byte[] payload) {
        if (payload.length < 5) return "Unknown error";
        int msgLen = ByteBuffer.wrap(payload, 1, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return new String(payload, 5, Math.min(msgLen, payload.length - 5));
    }
}
