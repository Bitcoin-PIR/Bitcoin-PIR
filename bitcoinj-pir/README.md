# bitcoinj-pir

A bitcoinj `UTXOProvider` that retrieves unspent outputs via Private Information Retrieval,
so the server never learns which addresses the wallet is querying.

Three PIR backends are supported:

| Backend | Servers | Native lib? | Typical latency |
|---------|---------|-------------|-----------------|
| **DPF** (distributed point function) | 2 | No (pure Java) | ~100 ms |
| **HarmonyPIR** (stateful 2-server) | 2 (hint + query) | Yes (Rust JNI) | ~2 s after hint download |
| **OnionPIR** (single-server FHE) | 1 | Yes (C++ JNA) | ~50 s |

## Requirements

- Java 21+
- bitcoinj 0.17

For HarmonyPIR: `libharmonypir_jni` built from the `harmonypir-jni` crate.
For OnionPIR: `libonionpir` built from the OnionPIRv2 repo.

## Quick start

```java
import com.bitcoinpir.*;

// DPF — no native libraries needed
var provider = new PirUtxoProvider(new PirBackendConfig.Dpf(
        "ws://server0:8091", "ws://server1:8092"));
provider.connect();
wallet.setUTXOProvider(provider);
Coin balance = wallet.getBalance();
provider.close();

// HarmonyPIR — requires harmonypir-jni native library
var provider = new PirUtxoProvider(new PirBackendConfig.Harmony(
        "ws://hint:8094", "ws://query:8095"));
provider.connect();
wallet.setUTXOProvider(provider);

// OnionPIR — requires libonionpir native library
var provider = new PirUtxoProvider(new PirBackendConfig.OnionPir(
        "ws://server:8093"));
provider.connect();
wallet.setUTXOProvider(provider);
```

## Build

```bash
./gradlew build
```

## Tests

Unit tests (no servers required):

```bash
./gradlew test --tests "*.HarmonyBucketTest"
./gradlew test --tests "*.PirUtxoProviderTest"
```

Integration tests (require running PIR servers and native libraries):

```bash
./gradlew cleanTest test --tests "*.IntegrationTest"
```

Native library paths default to:
- HarmonyPIR: `../../bitcoin-pir/harmonypir-jni/target/release`
- OnionPIR: `../electrum_plugin/onionpir-python`

Override with Gradle properties or environment variables:

```bash
./gradlew test -PharmonyLibDir=/path/to/lib -PonionLibDir=/path/to/lib
# or
export HARMONYPIR_LIB_DIR=/path/to/lib
export ONIONPIR_LIB_DIR=/path/to/lib
```

## Architecture

```
com.bitcoinpir
  PirUtxoProvider         UTXOProvider facade — dispatches to backend
  PirBackendConfig        Sealed interface: Dpf | Harmony | OnionPir
  PirClient               Common interface for all backends
  PirConstants            Protocol constants, server defaults

  dpf/
    DpfPirClient          2-server DPF backend (pure Java)
    DpfKeyGen, DpfKey     Distributed point function key generation
    Block128              AES-based PRG for DPF expansion

  harmony/
    HarmonyPirClient      2-server stateful PIR backend
    HarmonyBucket         JNI wrapper around harmonypir-jni (Rust)

  onionpir/
    OnionPirClient        Single-server FHE PIR backend
    OnionChunkCuckoo      6-hash cuckoo table for OnionPIR chunk packing

  codec/
    ProtocolCodec         Wire format encoding/decoding
    UtxoDecoder           UTXO entry deserialization
    Varint                CompactSize encoding

  hash/
    PirHash               SipHash-2-4, HASH160, tag derivation
    CuckooHash            3-hash cuckoo table lookups

  placement/
    PbcPlanner            Probabilistic batch code round planning

  net/
    PirWebSocket          WebSocket transport (OkHttp)

com.onionpir.jna
    OnionPirLibrary       JNA bindings for libonionpir (C++)
    OnionPirClient        FHE client (key gen, query, decrypt)
    OnionBuf, PirParamsInfo  Native memory helpers
```

## Protocol details

See [USAGE.md](USAGE.md) for the HarmonyPIR wire protocol, bucket API, and complete query flow.

## License

Same license as the parent BitcoinPIR project.
