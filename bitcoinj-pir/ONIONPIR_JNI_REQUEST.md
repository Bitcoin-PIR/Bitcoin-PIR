# Request: JNI-Compatible C Shared Library for OnionPIR

## Context

We are building a Java library (`bitcoinj-pir`) that integrates Private Information Retrieval with [bitcoinj](https://github.com/bitcoinj/bitcoinj), the widely-used Java Bitcoin library. The library implements bitcoinj's `UTXOProvider` interface so wallets can query UTXOs privately.

We support three PIR backends. DPF and HarmonyPIR are (or will be) pure Java. **OnionPIR requires a native library** because FHE operations are not feasible in pure Java.

We need the OnionPIRv2 C++ library to expose a small C FFI surface that Java can call via JNI or JNA. This is very similar to what you already provide for the Python ctypes interface (`libonionpir.so`/`.dylib`).

## What We Need

A shared library (`libonionpir_jni.so` / `libonionpir_jni.dylib`) that exports the following C functions. These mirror the existing Python ctypes interface almost exactly.

### Option A: Plain C Exports (Preferred — Works with JNA)

If you provide plain C functions (matching the existing `libonionpir` interface), Java can call them directly via [JNA](https://github.com/java-native-access/jna) with zero additional native code. This is the simplest approach.

```c
// ── Types ────────────────────────────────────────────────────────────────

typedef struct {
    uint8_t* data;
    size_t   len;
} OnionBuf;

// ── Functions to export ──────────────────────────────────────────────────

/**
 * Free a buffer returned by the library.
 */
void onion_free_buf(OnionBuf buf);

/**
 * Create a new FHE client for a database with num_entries rows.
 * Pass 0 for compiled-in defaults.
 * Returns an opaque handle.
 */
void* onion_client_new(uint64_t num_entries);

/**
 * Create a client from an existing secret key (for key reuse across sessions).
 */
void* onion_client_new_from_sk(
    uint64_t num_entries,
    uint64_t client_id,
    const uint8_t* sk_data,
    size_t sk_len
);

/**
 * Free a client handle.
 */
void onion_client_free(void* handle);

/**
 * Get the client's unique ID.
 */
uint64_t onion_client_get_id(void* handle);

/**
 * Export the client's secret key for persistence.
 * Caller must free with onion_free_buf().
 */
OnionBuf onion_client_export_secret_key(void* handle);

/**
 * Generate Galois keys for server-side FHE evaluation.
 * Typically 2-5 MB. Sent to server once during key registration.
 * Caller must free with onion_free_buf().
 */
OnionBuf onion_client_generate_galois_keys(void* handle);

/**
 * Generate GSW keys for server-side FHE evaluation.
 * Typically 1-2 MB. Sent to server once during key registration.
 * Caller must free with onion_free_buf().
 */
OnionBuf onion_client_generate_gsw_keys(void* handle);

/**
 * Generate an FHE-encrypted query for a specific entry index.
 * Returns ciphertext bytes to send to the server.
 * Caller must free with onion_free_buf().
 */
OnionBuf onion_client_generate_query(void* handle, uint64_t entry_index);

/**
 * Decrypt the server's FHE response and extract the plaintext entry.
 *
 * @param handle       client handle
 * @param entry_index  must match the index used in generate_query
 * @param resp_data    server response ciphertext bytes
 * @param resp_len     length of response
 * @return             decrypted entry data; caller must free with onion_free_buf()
 */
OnionBuf onion_client_decrypt_response(
    void* handle,
    uint64_t entry_index,
    const uint8_t* resp_data,
    size_t resp_len
);
```

### Option B: JNI Exports (Alternative)

If you prefer to build JNI directly, the Java native method signatures are:

```java
package com.bitcoinpir.jni;

public class OnionPirJni {
    static { System.loadLibrary("onionpir_jni"); }

    /** Create a new FHE client. Returns opaque handle. */
    public static native long createClient(long numEntries);

    /** Create a client from existing secret key. */
    public static native long createClientFromSk(long numEntries, long clientId, byte[] secretKey);

    /** Free a client handle. */
    public static native void destroyClient(long handle);

    /** Get client ID. */
    public static native long getClientId(long handle);

    /** Export secret key. */
    public static native byte[] exportSecretKey(long handle);

    /** Generate Galois keys (~2-5 MB). */
    public static native byte[] generateGaloisKeys(long handle);

    /** Generate GSW keys (~1-2 MB). */
    public static native byte[] generateGswKeys(long handle);

    /** Generate encrypted query for entry_index. */
    public static native byte[] generateQuery(long handle, long entryIndex);

    /** Decrypt server response. */
    public static native byte[] decryptResponse(long handle, long entryIndex, byte[] response);
}
```

The JNI C++ implementation would use the standard JNI header (`jni.h`) and call the existing OnionPIRv2 C++ API internally. Each method maps 1:1 to the C functions above.

**We prefer Option A** because it lets us use JNA on the Java side (no generated headers, no javah, simpler cross-platform loading).

## How We Use It

### Initialization (Once Per Session)

```
1. Create keygen client:       handle = onion_client_new(0)
2. Generate keys:              galoisKeys = generate_galois_keys(handle)
                               gswKeys = generate_gsw_keys(handle)
3. Export secret key:          sk = export_secret_key(handle)
4. Free keygen client:         onion_client_free(handle)

5. Create index-level client:  indexHandle = onion_client_new_from_sk(indexBins, clientId, sk)
6. Create chunk-level client:  chunkHandle = onion_client_new_from_sk(chunkBins, clientId, sk)

7. Register keys with server:  send galoisKeys + gswKeys via WebSocket
                               (wire format: [4B len][0x30][4B gk_len][gk][4B gsw_len][gsw])
8. Wait for ACK:               server replies [4B len][0x30]
```

### Per Query

```
1. Generate query:    queryBytes = onion_client_generate_query(indexHandle, binIndex)
2. Send to server:    via WebSocket (wire format below)
3. Receive response:  encrypted ciphertext bytes from server
4. Decrypt:           entryData = onion_client_decrypt_response(indexHandle, binIndex, response)
5. Parse entryData:   scan for matching tag / extract chunk data
```

### Wire Protocol

Key registration:
```
[4B len LE][1B variant=0x30]
[4B galoisKeys.length LE][galoisKeys bytes]
[4B gswKeys.length LE][gswKeys bytes]
```

Query request (index or chunk level):
```
[4B len LE][1B variant: 0x31=index, 0x32=chunk]
[2B roundId LE]
[1B numQueries]
Per query:
  [4B queryLen LE]
  [queryLen bytes: FHE ciphertext from generate_query()]
```

Query response:
```
[4B len LE][1B variant: 0x31 or 0x32]
[2B roundId LE]
[1B numResults]
Per result:
  [4B resultLen LE]
  [resultLen bytes: encrypted response → passed to decrypt_response()]
```

## What Already Exists

The Python ctypes wrapper (`electrum_plugin/onionpir-python/onionpir_ffi.py`) already calls these exact C functions from `libonionpir.so`. The C function signatures listed in Option A above are taken directly from that wrapper.

If `libonionpir` already exports these symbols, then **no new code may be needed** — we just need to confirm the shared library is built with these symbols exported and document the build process for Java users.

## Build Requirements

For Java/Android users, the shared library needs to be built for:
- **Linux x86_64** (most common server/desktop)
- **macOS aarch64** (Apple Silicon development)
- **macOS x86_64** (optional, Intel Macs)
- **Linux aarch64** (optional, ARM servers)

Build command (existing):
```bash
cd OnionPIRv2
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
# produces libonionpir.so or libonionpir.dylib
```

## Constraints

- The shared library must be loadable via `System.loadLibrary("onionpir")` (JNI) or `Native.load("onionpir", ...)` (JNA)
- All functions must be `extern "C"` (no C++ name mangling)
- The `OnionBuf` pattern (library-allocated buffer, caller frees via `onion_free_buf`) works well with JNA's `Pointer` type
- Thread safety: each client handle is used from a single thread. Multiple handles may exist concurrently.
