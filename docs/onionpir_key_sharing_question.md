# Question: Can OnionPIR key registration be shared across Server instances?

## Current situation

In the Bitcoin PIR system, we have **155 PirServer instances** (75 index + 80 chunk)
running on a single machine. Each has a different `num_entries` count within its level,
but within a level all instances share the same `num_entries`:
- 75 index servers: all have `num_entries = 8833`
- 80 chunk servers: all have `num_entries = 32562`

When a client connects, it sends encryption keys (Galois + GSW, ~600KB total).
Currently, `set_galois_key()` and `set_gsw_key()` are called **on every server instance
individually**:

```cpp
// Called 75 times for index level, 80 times for chunk level
for server in servers:
    server.set_galois_key(client_id, &galois_keys)  // ~15ms each
    server.set_gsw_key(client_id, &gsw_keys)        // ~15ms each
```

This takes **~1.1s for index (75 × 15ms)** and **~1.2s for chunk (80 × 15ms)**,
totaling **~2.3s per query session** just for key registration.

## The question

The raw key bytes (Galois keys, GSW keys) are **identical** across all 75 index servers
(and identical across all 80 chunk servers). Each `set_galois_key` / `set_gsw_key` call
deserializes the same bytes into SEAL's internal `GaloisKeys` / `KSwitchKeys` objects.

**Is there a way to:**

1. **Deserialize the keys once** and share the deserialized SEAL objects across all
   PirServer instances at the same level?

2. **Store keys in a shared structure** (e.g., a `shared_ptr<GaloisKeys>`) that all
   servers reference, instead of each server holding its own copy?

3. **Add a bulk registration API** like:
   ```cpp
   // Hypothetical API — register keys once, share across all servers at this level
   static void register_shared_keys(
       vector<Server*>& servers,
       uint32_t client_id,
       const vector<uint8_t>& galois_keys,
       const vector<uint8_t>& gsw_keys
   );
   ```

## Why this matters

- **2.3s overhead per query** — about 25% of the total ~10s query time
- The keys are byte-identical across all servers at the same level
- All servers at the same level share the same SEAL parameters (same `num_entries`)
- The deserialization work (`load` from bytes → SEAL objects) is repeated 75-80× unnecessarily

## What I suspect

Looking at SEAL's `GaloisKeys` / `KSwitchKeys`, they are essentially serialized
ciphertexts keyed by Galois element indices. The internal representation depends on
the encryption parameters (poly_modulus_degree, coeff_modulus), which are the **same**
across all servers at the same level (since they all have the same `num_entries`).

So the deserialized key objects should be **structurally identical** and **safely shareable**
(read-only during `answer_query`).

## Possible implementation

In `server.h` / `server.cpp`:

```cpp
class Server {
    // Current: each server owns its own key maps
    // map<uint32_t, GaloisKeys> galois_keys_;
    // map<uint32_t, GSWCiphertext> gsw_keys_;

    // Proposed: servers can share key storage via shared_ptr
    shared_ptr<map<uint32_t, GaloisKeys>> shared_galois_keys_;
    shared_ptr<map<uint32_t, GSWCiphertext>> shared_gsw_keys_;
};

// New API: deserialize once, share across all servers
void Server::set_shared_key_store(
    shared_ptr<map<uint32_t, GaloisKeys>> galois_store,
    shared_ptr<map<uint32_t, GSWCiphertext>> gsw_store
);

// Single deserialization point
static pair<GaloisKeys, GSWCiphertext> Server::deserialize_keys(
    uint32_t client_id,
    const vector<uint8_t>& galois_bytes,
    const vector<uint8_t>& gsw_bytes
);
```

This would reduce key registration from **~2.3s → ~30ms** (one deserialization per level).

## Impact on Bitcoin PIR

| | Current | With shared keys |
|---|---|---|
| Index key registration | ~1.1s (75 × 15ms) | ~15ms (1 × 15ms) |
| Chunk key registration | ~1.2s (80 × 15ms) | ~15ms (1 × 15ms) |
| Total key overhead | ~2.3s | ~30ms |
| % of query time | ~25% | ~0.3% |
