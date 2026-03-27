package com.onionpir.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Safe wrapper around an OnionPIR client handle.
 * <p>
 * Each client is bound to a specific database size (num_entries).
 * Use {@link #fromSecretKey} to create additional clients that share
 * the same FHE keys but target a different database size.
 * <p>
 * Example:
 * <pre>{@code
 * try (OnionPirClient client = new OnionPirClient(1 << 16)) {
 *     byte[] galoisKeys = client.generateGaloisKeys();
 *     byte[] gswKeys    = client.generateGswKeys();
 *     byte[] query      = client.generateQuery(42);
 *     // ... send keys + query to server, receive response ...
 *     byte[] entry      = client.decryptResponse(42, serverResponse);
 * }
 * }</pre>
 * <p>
 * Thread safety: a single client instance must not be shared across threads.
 */
public class OnionPirClient implements AutoCloseable {

    private static final OnionPirLibrary LIB = OnionPirLibrary.INSTANCE;

    private Pointer handle;

    /**
     * Create a new FHE client for a database with {@code numEntries} rows.
     * Pass 0 to use the compiled-in default.
     */
    public OnionPirClient(long numEntries) {
        handle = LIB.onion_client_new(numEntries);
        if (handle == null) {
            throw new RuntimeException("Failed to create OnionPirClient");
        }
    }

    private OnionPirClient(Pointer handle) {
        this.handle = handle;
    }

    /**
     * Create a client from an existing secret key (exported via {@link #exportSecretKey}).
     * The new client shares the same FHE keys but can target a different database size.
     */
    public static OnionPirClient fromSecretKey(long numEntries, long clientId, byte[] secretKey) {
        Pointer h = LIB.onion_client_new_from_sk(
                numEntries, clientId, secretKey, new NativeLong(secretKey.length));
        if (h == null) {
            throw new RuntimeException("Failed to create OnionPirClient from secret key");
        }
        return new OnionPirClient(h);
    }

    /** Get the client's unique ID (randomly assigned at creation). */
    public long getId() {
        return LIB.onion_client_get_id(handle);
    }

    /** Export the secret key for persistence or creating per-database clients. */
    public byte[] exportSecretKey() {
        return OnionPir.bufToBytes(LIB.onion_client_export_secret_key(handle));
    }

    /** Generate Galois keys (~2-5 MB) to send to the server during key registration. */
    public byte[] generateGaloisKeys() {
        return OnionPir.bufToBytes(LIB.onion_client_generate_galois_keys(handle));
    }

    /** Generate GSW keys (~1-2 MB) to send to the server during key registration. */
    public byte[] generateGswKeys() {
        return OnionPir.bufToBytes(LIB.onion_client_generate_gsw_keys(handle));
    }

    /** Generate an FHE-encrypted query for the given entry index. */
    public byte[] generateQuery(long entryIndex) {
        return OnionPir.bufToBytes(LIB.onion_client_generate_query(handle, entryIndex));
    }

    /**
     * Decrypt the server's FHE response and extract the plaintext entry.
     *
     * @param entryIndex must match the index used in {@link #generateQuery}
     * @param response   encrypted response bytes from the server
     * @return decrypted entry data
     */
    public byte[] decryptResponse(long entryIndex, byte[] response) {
        return OnionPir.bufToBytes(LIB.onion_client_decrypt_response(
                handle, entryIndex, response, new NativeLong(response.length)));
    }

    @Override
    public void close() {
        if (handle != null) {
            LIB.onion_client_free(handle);
            handle = null;
        }
    }

    /** Package-private handle access for interop with other wrappers. */
    Pointer getHandle() {
        return handle;
    }
}
