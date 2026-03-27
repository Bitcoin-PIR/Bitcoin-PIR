package com.bitcoinpir;

import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.dpf.DpfPirClient;
import com.bitcoinpir.harmony.HarmonyBucket;
import com.bitcoinpir.harmony.HarmonyPirClient;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.onionpir.OnionPirClient;

import org.junit.jupiter.api.*;

import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests for all three PIR backends.
 *
 * <p>Requires local servers running:
 * <ul>
 *   <li>DPF: ws://localhost:8091 + ws://localhost:8092</li>
 *   <li>OnionPIR: ws://localhost:8093</li>
 *   <li>HarmonyPIR hint: ws://localhost:8094, query: ws://localhost:8095</li>
 * </ul>
 *
 * <p>Enable tests by removing @Disabled or run:
 * <pre>
 *   ./gradlew test --tests "com.bitcoinpir.IntegrationTest" \
 *     -PharmonyLibDir=/path/to/harmonypir-jni/target/release \
 *     -PonionLibDir=/path/to/OnionPIRv2/build-shared
 * </pre>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class IntegrationTest {

    // ── Server URLs ─────────────────────────────────────────────────────────

    static final String DPF_SERVER0 = "ws://localhost:8091";
    static final String DPF_SERVER1 = "ws://localhost:8092";
    static final String ONIONPIR_SERVER = "ws://localhost:8093";
    static final String HARMONY_HINT_SERVER = "ws://localhost:8094";
    static final String HARMONY_QUERY_SERVER = "ws://localhost:8095";

    // ── Test addresses ──────────────────────────────────────────────────────

    /** Satoshi's P2PKH — likely a whale, may return empty (whale flag). */
    static final String SATOSHI_SPK = "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac";

    /** 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 — normal P2PKH. */
    static final String NORMAL_P2PKH_SPK = "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac";

    /** 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy — P2SH address. */
    static final String P2SH_SPK = "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87";

    // ══════════════════════════════════════════════════════════════════════════
    //  Test 1: DPF (pure Java — no native deps)
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(1)
    void testDpfConnectAndQuery() throws Exception {
        System.out.println("═══ DPF: Connect & Query ═══");

        try (var client = new DpfPirClient(DPF_SERVER0, DPF_SERVER1)) {
            long t0 = System.currentTimeMillis();
            client.connect();
            long connectMs = System.currentTimeMillis() - t0;

            assertTrue(client.isConnected());
            System.out.printf("  Connected in %d ms%n", connectMs);

            // Query Satoshi's address
            var results = queryAddress(client, SATOSHI_SPK);
            System.out.printf("  Satoshi UTXOs: %d%n", results.size());
            printUtxos(results);

            // Also try the normal address
            var normalResults = queryAddress(client, NORMAL_P2PKH_SPK);
            System.out.printf("  Normal P2PKH UTXOs: %d%n", normalResults.size());
            printUtxos(normalResults);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Tests 2-4: HarmonyPIR with three PRP backends
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(2)
    void testHarmonyAlf() throws Exception {
        assumeHarmonyNative();
        runHarmonyTest("ALF", HarmonyBucket.PRP_ALF);
    }

    @Test
    @Order(3)
    void testHarmonyHoang() throws Exception {
        assumeHarmonyNative();
        runHarmonyTest("HOANG", HarmonyBucket.PRP_HOANG);
    }

    @Test
    @Order(4)
    void testHarmonyFastPrp() throws Exception {
        assumeHarmonyNative();
        runHarmonyTest("FASTPRP", HarmonyBucket.PRP_FASTPRP);
    }

    private void runHarmonyTest(String prpName, int prpBackend) throws Exception {
        System.out.printf("═══ HarmonyPIR [%s]: Connect & Query ═══%n", prpName);

        try (var client = new HarmonyPirClient(HARMONY_HINT_SERVER, HARMONY_QUERY_SERVER, prpBackend)) {
            long t0 = System.currentTimeMillis();
            client.connect();
            long connectMs = System.currentTimeMillis() - t0;

            assertTrue(client.isConnected());
            System.out.printf("  Connected in %d ms (includes hint download)%n", connectMs);

            // Query Satoshi's address
            long qt0 = System.currentTimeMillis();
            var results = queryAddress(client, SATOSHI_SPK);
            long queryMs = System.currentTimeMillis() - qt0;

            System.out.printf("  Satoshi UTXOs: %d (query %d ms)%n", results.size(), queryMs);
            printUtxos(results);

            // Normal address
            var normalResults = queryAddress(client, NORMAL_P2PKH_SPK);
            System.out.printf("  Normal P2PKH UTXOs: %d%n", normalResults.size());
            printUtxos(normalResults);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Test 5: OnionPIR (JNA → C++ FHE)
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(5)
    void testOnionPirConnectAndQuery() throws Exception {
        assumeOnionNative();
        System.out.println("═══ OnionPIR: Connect & Query ═══");

        try (var client = new OnionPirClient(ONIONPIR_SERVER)) {
            long t0 = System.currentTimeMillis();
            client.connect();
            long connectMs = System.currentTimeMillis() - t0;

            assertTrue(client.isConnected());
            System.out.printf("  Connected in %d ms (includes FHE key registration)%n", connectMs);

            // Query Satoshi's address
            long qt0 = System.currentTimeMillis();
            var results = queryAddress(client, SATOSHI_SPK);
            long queryMs = System.currentTimeMillis() - qt0;

            System.out.printf("  Satoshi UTXOs: %d (query %d ms)%n", results.size(), queryMs);
            printUtxos(results);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Test 6: Cross-backend consistency
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(6)
    void testCrossBackendConsistency() throws Exception {
        assumeHarmonyNative();
        System.out.println("═══ Cross-Backend Consistency ═══");

        // Use the normal P2PKH address (non-whale)
        byte[] hash = scriptHash(NORMAL_P2PKH_SPK);

        // DPF query
        List<UtxoDecoder.UtxoEntry> dpfResults;
        try (var dpf = new DpfPirClient(DPF_SERVER0, DPF_SERVER1)) {
            dpf.connect();
            var results = dpf.queryBatch(List.of(hash));
            dpfResults = results.getOrDefault(0, List.of());
        }
        System.out.printf("  DPF: %d UTXOs%n", dpfResults.size());

        // HarmonyPIR ALF query
        List<UtxoDecoder.UtxoEntry> harmonyResults;
        try (var harmony = new HarmonyPirClient(HARMONY_HINT_SERVER, HARMONY_QUERY_SERVER, HarmonyBucket.PRP_ALF)) {
            harmony.connect();
            var results = harmony.queryBatch(List.of(hash));
            harmonyResults = results.getOrDefault(0, List.of());
        }
        System.out.printf("  HarmonyPIR ALF: %d UTXOs%n", harmonyResults.size());

        // Compare
        Set<String> dpfSet = toUtxoSet(dpfResults);
        Set<String> harmonySet = toUtxoSet(harmonyResults);

        System.out.printf("  DPF set:     %s%n", dpfSet);
        System.out.printf("  Harmony set: %s%n", harmonySet);

        assertEquals(dpfSet, harmonySet,
                "DPF and HarmonyPIR should return identical UTXO sets");
        System.out.println("  ✓ UTXO sets match!");
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Test 7: DPF multi-address batch
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(7)
    void testDpfMultiAddressBatch() throws Exception {
        System.out.println("═══ DPF: Multi-Address Batch ═══");

        byte[] hash1 = scriptHash(NORMAL_P2PKH_SPK);
        byte[] hash2 = scriptHash(P2SH_SPK);

        try (var client = new DpfPirClient(DPF_SERVER0, DPF_SERVER1)) {
            client.connect();

            long t0 = System.currentTimeMillis();
            var results = client.queryBatch(List.of(hash1, hash2));
            long queryMs = System.currentTimeMillis() - t0;

            System.out.printf("  Batch query completed in %d ms%n", queryMs);

            var r0 = results.getOrDefault(0, List.of());
            var r1 = results.getOrDefault(1, List.of());
            System.out.printf("  Address 0 (P2PKH):  %d UTXOs%n", r0.size());
            printUtxos(r0);
            System.out.printf("  Address 1 (P2SH):   %d UTXOs%n", r1.size());
            printUtxos(r1);

            // Both results should exist (even if empty)
            assertNotNull(results.get(0), "Result for address 0 should exist");
            assertNotNull(results.get(1), "Result for address 1 should exist");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Test 8: PirUtxoProvider with DPF backend
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(8)
    void testPirUtxoProviderDpf() throws Exception {
        System.out.println("═══ PirUtxoProvider: DPF Backend ═══");

        var config = new PirBackendConfig.Dpf(DPF_SERVER0, DPF_SERVER1);
        try (var provider = new PirUtxoProvider(config)) {
            provider.connect();

            int height = provider.getChainHeadHeight();
            System.out.printf("  Chain height: %d%n", height);
            assertTrue(height > 800_000, "Chain height should be recent");

            assertEquals(org.bitcoinj.base.BitcoinNetwork.MAINNET, provider.network());
            System.out.println("  Network: MAINNET ✓");
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** Compute HASH160 of a scriptPubKey hex string. */
    private static byte[] scriptHash(String spkHex) {
        return PirHash.hash160(PirHash.hexToBytes(spkHex));
    }

    /** Query a single address via a PirClient. */
    private static List<UtxoDecoder.UtxoEntry> queryAddress(PirClient client, String spkHex) throws Exception {
        byte[] hash = scriptHash(spkHex);
        var results = client.queryBatch(List.of(hash));
        return results.getOrDefault(0, List.of());
    }

    /** Print UTXO entries for debugging. */
    private static void printUtxos(List<UtxoDecoder.UtxoEntry> entries) {
        int limit = Math.min(entries.size(), 10);
        for (int i = 0; i < limit; i++) {
            var e = entries.get(i);
            String txid = PirHash.bytesToHex(PirHash.reverseBytes(e.txid()));
            System.out.printf("    [%d] txid=%s vout=%d amount=%d sats%n",
                    i, txid, e.vout(), e.amount());
        }
        if (entries.size() > 10) {
            System.out.printf("    ... and %d more%n", entries.size() - 10);
        }
    }

    /** Convert a UTXO list to a comparable set of "txid:vout:amount" strings. */
    private static Set<String> toUtxoSet(List<UtxoDecoder.UtxoEntry> entries) {
        return entries.stream()
                .map(e -> PirHash.bytesToHex(e.txid()) + ":" + e.vout() + ":" + e.amount())
                .collect(Collectors.toSet());
    }

    /** Skip test if HarmonyPIR JNI native library is not available. */
    private static void assumeHarmonyNative() {
        Assumptions.assumeTrue(HarmonyBucket.isNativeLoaded(),
                "harmonypir_jni native library not available — skipping");
    }

    /** Skip test if OnionPIR JNA native library is not available. */
    private static void assumeOnionNative() {
        boolean available;
        try {
            Class.forName("com.onionpir.jna.OnionPirLibrary");
            // Try to actually load the native library
            com.onionpir.jna.OnionPirLibrary lib = com.onionpir.jna.OnionPirLibrary.INSTANCE;
            available = (lib != null);
        } catch (Throwable t) {
            available = false;
        }
        Assumptions.assumeTrue(available,
                "OnionPIR JNA native library not available — skipping");
    }
}
