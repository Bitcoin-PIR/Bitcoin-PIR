# Terminology Glossary

Canonical naming for the BitcoinPIR codebase. A new reader should be able to
understand the system by reading this page.

## PIR levels

| Term | Definition |
|------|-----------|
| **INDEX level** | First PIR lookup: script_hash -> chunk location. K=75 PBC groups. |
| **CHUNK level** | Second PIR lookup: chunk_id -> UTXO data. K=80 PBC groups. |

## PBC (Probabilistic Batch Code)

| Term | Variable | Definition |
|------|----------|-----------|
| **PBC group** | `group_id` | One of K partitions (K=75 INDEX, K=80 CHUNK). Each item is assigned to 3 candidate groups via cuckoo hashing. Each group has its own cuckoo table. |
| **round** | `round_id` | One parallel query batch across all K groups. Multi-chunk addresses may need multiple rounds. |

## Cuckoo hash table

| Term | Variable | Definition |
|------|----------|-----------|
| **cuckoo table** | `table` | The hash table for one PBC group. Size = `bins_per_table * slots_per_bin * slot_size` bytes. |
| **bin** | `bin` | A location in a cuckoo hash table. Items hash to bins via 2-hash cuckoo hashing. |
| **slot** | `slot` | A position within a bin. Each bin holds `slots_per_bin` slots. |
| **slots_per_bin** | `slots_per_bin` | Number of slots per cuckoo bin. INDEX=4, CHUNK=3. (Previously `cuckoo_bucket_size`.) |
| **bins_per_table** | `bins_per_table` | Total bins in one group's cuckoo table, computed from load factor. |

## Data sizes

| Term | Constant | Size | Layout |
|------|----------|------|--------|
| **index record** | `INDEX_RECORD_SIZE` | 25B | 20B script_hash + 4B start_chunk_id + 1B num_chunks. Intermediate file format. |
| **index slot** | `INDEX_SLOT_SIZE` | 17B | 8B tag + 4B start_chunk_id + 1B num_chunks + 4B tree_loc. Cuckoo table format. |
| **chunk slot** | `CHUNK_SLOT_SIZE` | 44B | 4B chunk_id + 40B data. |
| **chunk** | `CHUNK_SIZE` | 40B | One UTXO data segment. |
| **PIR entry** | (OnionPIR) | varies | One FHE plaintext element = one cuckoo bin = `slots_per_bin * slot_size` bytes. |

## Protocol backends

| Term | Description |
|------|-----------|
| **DPF** | 2-server Distributed Point Function. Client sends DPF keys to both servers. |
| **HarmonyPIR** | 2-server stateful PIR with offline hints. Each PBC group is a WASM `HarmonyGroup` instance. |
| **OnionPIR** | 1-server FHE-based PIR (OnionPIRv2). Each PBC group has its own preprocessed OnionPIR database. |

## OnionPIR note

OnionPIR's internal `push_chunk()` method refers to FHE plaintext subdivisions,
**not** UTXO data chunks. This is an upstream API name we cannot rename.
