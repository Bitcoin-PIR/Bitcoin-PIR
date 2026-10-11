# Wire protocol v1

The messages a client and `unified_server` exchange: framing, the encrypted
channel, the opcode registry with each message's wire shape, errors, the
retired opcodes, and the stability policy. Terms are defined in
[GLOSSARY.md](../GLOSSARY.md). Query padding and the symmetry rules that keep
a query private are client behaviour, specified in
[VERIFICATION_OVERVIEW.md](VERIFICATION_OVERVIEW.md) and not restated here.

The code is the source of truth. Each shape names its encoder; line numbers
are as of this page's last edit, and the function name is the stable handle.
`protocol.rs` is `crates/protocol/runtime/src/protocol.rs`; `dispatch.rs`,
`serve.rs`, `io.rs`, `state.rs`, `oram.rs`, `credit_meter.rs` and
`credit_gate.rs` are in `apps/server/src/bin/unified_server/`; `onionpir.rs`
and `hint_pool.rs` are in `apps/server/src/`. The Rust SDK
(`crates/sdk/client`) and the web client (`web/src`) keep their own copies of
the opcodes they send.

## Transport and framing

- A server accepts WebSocket connections (`ws://`; TLS, if any, is the
  operator's proxy or tunnel). Binary messages carry the protocol; a
  WebSocket ping gets a pong and text messages are ignored.
- Integers are little-endian. A *record* is `[len u32][payload]`, where
  `len` counts the payload. `payload[0]` is the opcode of a cleartext
  record, or `0xfe` for a sealed one.
- Client to server: one record per WebSocket message. Server to client: one
  record per message, except the HarmonyPIR hint streams, which pack records
  into messages of about 768 KiB (`send_resp_batch`, io.rs:259); a client
  reads the records of a message in order.
- Chunk envelope: a long record can travel as chunk frames
  `[len u32][0xc7][seq u16][total u16][piece]`, pieces of at most 256 KiB in
  order `seq = 0 … total−1`, reassembled before anything else reads the
  record (serve.rs:222). A server takes WebSocket messages of at most
  512 KiB (`MAX_WS_MESSAGE_BYTES`, io.rs:332) and reassembled requests of at
  most 16 MiB (`MAX_REASSEMBLED`); the clients chunk every request above
  256 KiB. The server chunks a response above 256 KiB for `0x34` and `0x43`
  always, and for OnionPIR (`0x50`–`0x56`) once the client has sent a chunk
  frame on the connection (`send_resp_chunked`, io.rs:133).
- Sealing happens inside the envelope: a sealed record is chunked, and the
  receiver reassembles before it opens.

## Encrypted channel

The channel keeps query bytes from anything between client and server, such
as a TLS-terminating tunnel. Its primitives are in `pir-channel`
(`crates/protocol/channel/src/lib.rs:22`).

1. `REQ_ATTEST` returns the server's per-boot X25519 key
   `server_static_pub`, bound into the SEV-SNP report on a host that has
   one; `REQ_ANNOUNCE` binds it to an operator-signed identity. Which of
   these a client requires is the client's choice.
2. `REQ_HANDSHAKE` `[client_eph_pub 32][nonce 32]` → `RESP_HANDSHAKE`
   `[server_eph_pub 32]`, both cleartext. The session key is
   HKDF-SHA256 with salt `nonce`, input
   `X25519(client_eph, server_static) ‖ X25519(client_eph, server_eph)` and
   info `BPIR-CHANNEL-V1`. One handshake per connection; a second is refused.
3. A sealed record is `[len u32][0xfe][seq u64][ciphertext ‖ tag 16]`: the
   inner payload `[opcode][body]` under ChaCha20-Poly1305 (`Session::seal`,
   lib.rs:309). The nonce is `[direction u32][seq u64]`, direction 0 for
   client to server and 1 for server to client; each direction counts `seq`
   from 0, and a receiver accepts only the next one.

Before the handshake every opcode works in cleartext except `0x12`
(`REQ_CREDIT_PRESENT`), `0x13` (`REQ_API_KEY`) and `0x60`
(`REQ_ORAM_LOOKUP`): they carry bearer secrets or plaintext scripthashes, and
the server refuses them with `RESP_ERROR` unless they arrive sealed. After
the handshake the server still accepts cleartext requests, but it seals
every record it sends, those replies included. A sealed record on a
connection without a session, or one that fails to open, gets `RESP_ERROR`
(serve.rs:311).

## Gates and metering

The operator sets these per server (serve.rs:364;
[Operator guide](OPERATOR_GUIDE.md)):

- `--serve-queries`: the query opcodes `0x11 0x21 0x33 0x34 0x43 0x50–0x56
  0x60` (`is_query_bearing_variant`, serve.rs:20). Without it they get
  `RESP_ERROR`; with `--oram-only`, `0x60` is the only one served.
- `--serve-hints`: the HarmonyPIR hint requests `0x41 0x44 0x46`.
- OnionPIR opcodes are answered by a server that loaded OnionPIR databases
  (primary role); elsewhere they are unsupported. `0x60` needs a build with
  `--features cuckoo-oram` and a Direct ORAM database.
- Metering ([Credits and gas](CREDITS.md)): every query and hint opcode is
  priced in gas and assigned a backend (`dpf`, `harmony`, `onion`, `oram`) by
  `metered_op_for_frame` (credit_meter.rs:104). The backend's access policy
  then serves the frame free, charges the connection's credits, or serves it
  on a best-effort free lane. A connection that presented an accepted API
  key is unmetered. The other opcodes are never metered.

## Registry

A response carries its request's opcode, except `RESP_ERROR` (`0xff`) and
the hint streams (`0x41` records, after a `0x44` key preamble for V2).
*Channel*: **any** is cleartext or sealed, **sealed** is refused unless
sealed, **clear** is cleartext once per connection. *Gate* and *Metered* are
explained above. "→ same" is the request's name with `RESP_`.

| Op | Request → response | Purpose | Channel | Gate | Metered |
|---|---|---|---|---|---|
| `0x00` | `REQ_PING` → `RESP_PONG` | keepalive | any | — | — |
| `0x01` | `REQ_GET_INFO` → `RESP_INFO` | main database geometry, binary | any | — | — |
| `0x02` | `REQ_GET_DB_CATALOG` → `RESP_DB_CATALOG` | every database's geometry and anchor | any | — | — |
| `0x03` | `REQ_GET_INFO_JSON` → same | server info, JSON | any | — | — |
| `0x05` | `REQ_ATTEST` → `RESP_ATTEST` | attestation and channel key | any | — | — |
| `0x06` | `REQ_HANDSHAKE` → `RESP_HANDSHAKE` | open the encrypted channel | clear | — | — |
| `0x07` | `REQ_ANNOUNCE` → `RESP_ANNOUNCE` | operator-signed identity | any | — | — |
| `0x0a` | `REQ_GET_DB_PROOF` → `RESP_DB_PROOF` | database proof, bundle v1 | any | — | — |
| `0x0c` | `REQ_GET_DB_PROOF_V2` → `RESP_DB_PROOF_V2` | database proof, bundle v2 | any | — | — |
| `0x11` | `REQ_INDEX_BATCH` → same | DPF INDEX round | any | queries | dpf |
| `0x12` | `REQ_CREDIT_PRESENT` → `RESP_CREDIT_OK` | present credits | sealed | — | — |
| `0x13` | `REQ_API_KEY` → `RESP_API_KEY_OK` | present an API key | sealed | — | — |
| `0x21` | `REQ_CHUNK_BATCH` → same | DPF CHUNK round | any | queries | dpf |
| `0x33` | `REQ_BUCKET_MERKLE_SIB_BATCH` → same | DPF Merkle sibling pass | any | queries | dpf |
| `0x34` | `REQ_BUCKET_MERKLE_TREE_TOPS` → same | DPF and HarmonyPIR Merkle tree-tops | any | queries | dpf |
| `0x40` | `REQ_HARMONY_GET_INFO` → `RESP_HARMONY_INFO` | as `0x01` | any | — | — |
| `0x41` | `REQ_HARMONY_HINTS` → `RESP_HARMONY_HINTS` × n | hints, client-chosen key | any | hints | harmony |
| `0x43` | `REQ_HARMONY_BATCH_QUERY` → same | HarmonyPIR query round | any | queries | harmony |
| `0x44` | `REQ_HARMONY_HINTS_V2` → `RESP_HARMONY_HINTS_KEY`, `0x41` × n | hints, server-chosen key | any | hints | harmony |
| `0x46` | `REQ_HARMONY_HINTS_V2_HALF` → as `0x44` | one half of a V2 hint set | any | hints | harmony |
| `0x50` | `REQ_REGISTER_KEYS` → `RESP_KEYS_ACK` | upload FHE evaluation keys | any | queries | onion |
| `0x51` | `REQ_ONIONPIR_INDEX_QUERY` → `RESP_ONIONPIR_INDEX_RESULT` | OnionPIR INDEX round | any | queries | onion |
| `0x52` | `REQ_ONIONPIR_CHUNK_QUERY` → `RESP_ONIONPIR_CHUNK_RESULT` | OnionPIR CHUNK round | any | queries | onion |
| `0x53` | `REQ_ONIONPIR_MERKLE_INDEX_SIBLING` → same | OnionPIR INDEX Merkle siblings | any | queries | onion |
| `0x54` | `REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP` → same | OnionPIR Merkle tree-tops | any | queries | onion |
| `0x55` | `REQ_ONIONPIR_MERKLE_DATA_SIBLING` → same | OnionPIR DATA Merkle siblings | any | queries | onion |
| `0x56` | `REQ_ONIONPIR_MERKLE_DATA_TREE_TOP` → same | OnionPIR Merkle tree-tops | any | queries | onion |
| `0x60` | `REQ_ORAM_LOOKUP` → `RESP_ORAM_LOOKUP` | Direct ORAM lookup | sealed | queries | oram |
| `0xff` | — → `RESP_ERROR` | any refusal or failure | — | — | — |

## Wire shapes

A body follows the opcode byte. *opt `db_id`* is one trailing byte naming
the database, sent only when it is not 0.

### Discovery and trust

- `0x00`: empty → empty.
- `0x01` and `0x40`: empty → `[index_bins u32][chunk_bins u32][index_k u8]
  [chunk_k u8][tag_seed u64][index_master_seed u64][chunk_master_seed u64]
  [anchor]` for the main database (`Response::encode`, protocol.rs:887). An
  anchor is `[kind u8]` plus 0, 36 or 72 bytes for none, snapshot or delta
  (`encode_anchor_ext`, protocol.rs:2022).
- `0x02`: empty → `[n u8]`, n entries `[db_id u8][db_type u8][name_len u8]
  [name][base_height u32][height u32][index_bins u32][chunk_bins u32]
  [index_k u8][chunk_k u8][tag_seed u64][dpf_n_index u8][dpf_n_chunk u8]
  [has_bucket_merkle u8]`, then `[0x01]` and per entry
  `[index_master_seed u64][chunk_master_seed u64][anchor]`
  (`encode_db_catalog`, protocol.rs:1828).
- `0x03`: empty → UTF-8 JSON with the database parameters, OnionPIR
  parameters, Merkle roots, the gas card and the access policy
  (`server_info_json`, state.rs:259).
- `0x05`: `[nonce 32]` → `[report_len u32][SEV-SNP report][n u8]
  [n × manifest_root 32][binary_sha256 32][server_static_pub 32]
  [git_rev_len u16][git_rev]`, then `[len u32][PEM]` for the AMD ARK, ASK and
  VCEK certificates; the report and PEMs are empty where unavailable
  (`encode_attest_result`, protocol.rs:2076).
- `0x06`: see [Encrypted channel](#encrypted-channel).
- `0x07`: empty → `[len u32][bundle]`, the bundle being
  `[cert_len u32][IdentityCert][manifest_len u32][ChannelManifest]`
  (`AnnouncementBundle::encode`, `crates/trust/identity/src/lib.rs:629`). A
  server without an identity answers `RESP_ERROR`.
- `0x0a` and `0x0c`: exactly `[db_id u8]` → `[version u16][db_id u8]`
  (version 1 or 2), then six `[len u32][bytes]` fields: build evidence,
  root-bundle payload, SEV-SNP report, database-manifest SHA-256,
  all-artifacts-manifest SHA-256 and the server-db manifest TOML
  (`encode_db_proof_bundle`, protocol.rs:1968).

### Credits

- `0x12`: `[kind u8][len u32][payload]`, payload at most 256 KiB →
  `RESP_CREDIT_OK` `[gas_added u64][gas_balance i64]` (`Request::encode`,
  protocol.rs:724). Kind `1` is a Cashu token (`cashuB…` as UTF-8,
  `CREDIT_PRESENT_KIND_CASHU`); a server refuses any other kind. The gas
  belongs to the connection and ends with it.
- `0x13`: the key, 1 to 128 bytes → `RESP_API_KEY_OK`, empty.

### DPF

- `0x11`, `0x21`, `0x33`: `[round_id u16][num_groups u8][keys_per_group u8]`,
  then `[key_len u16][DPF key]` per key of each group, opt `db_id`
  (`encode_batch_query`, protocol.rs:1198). INDEX groups carry two keys, one
  per cuckoo position; every key must pass `validate_dpf_key_bytes`. For
  `0x33`, `round_id = table × 100 + level` (table 0 INDEX, 1 CHUNK). Response:
  `[round_id u16][num_groups u8][results_per_group u8]`, then
  `[len u16][result]` each (`encode_batch_result`, protocol.rs:1297).
- `0x34`: optional `[db_id u8]` → the database's
  `merkle_bucket_tree_tops.bin`, verbatim (dispatch.rs:350).

### HarmonyPIR

- `0x41`: `[prp_key 16][prp_backend u8][level u8][n u8][n × group_id u8]`,
  opt `db_id` → one `RESP_HARMONY_HINTS` record per group,
  `[group_id u8][n u32][t u32][m u32][hints]` (dispatch.rs:401; the record
  is built by `compute_and_serialize_hint_frame`, hint_pool.rs:518).
- `0x44`: `[0xff][0x00]`, opt `db_id` → `RESP_HARMONY_HINTS_KEY`
  `[prp_backend u8][0xff][total_groups u8][prp_key 16]`
  (`build_key_preamble`, hint_pool.rs:102), the `0x41` records of every
  INDEX then every CHUNK group, and the end marker `[0x41][0xff]`
  (dispatch.rs:500).
- `0x46`: `[session_token 16, not all zero][side u8: 0 INDEX, 1 CHUNK]`, opt
  `db_id` → as `0x44`, with one side's records. The two requests that share
  a token, one per side, get the same server-chosen key (dispatch.rs:615).
- `0x43`: `[level u8][round_id u16][num_groups u16][sub_queries u8]`, then per
  group `[group_id u8]` and per sub-query `[count u32][count × index u32]`,
  opt `db_id` (`encode_harmony_batch_query`, protocol.rs:1488) →
  `[level u8][round_id u16][num_groups u16][sub_results u8]`, then per group
  `[group_id u8]` and per sub-result `[len u32][bytes]`
  (`encode_harmony_batch_result`, protocol.rs:1575). Levels: 0 INDEX,
  1 CHUNK, `10 + l` INDEX sibling level `l`, `20 + l` CHUNK sibling level `l`
  (`pir_credit::gas::harmony_level`).

### OnionPIR

- `0x50`: `[galois_len u32][galois_keys][gsw_len u32][gsw_keys]`, opt
  `db_id` (`RegisterKeysMsg`, onionpir.rs:45) → `RESP_KEYS_ACK`, empty.
- `0x51`, `0x52`, `0x53`, `0x55`: `[round_id u16][n u8]`, then
  `[len u32][query]` per group, opt `db_id` (`OnionPirBatchQuery`,
  onionpir.rs:118) → `[round_id u16][n u8]`, then `[len u32][reply]` each
  (`OnionPirBatchResult`, onionpir.rs:191). For the sibling opcodes,
  `round_id = sibling_level × 100 + round`.
- `0x54` and `0x56`: optional `[db_id u8]` → the database's
  `merkle_onion_tree_tops.bin` (every INDEX and DATA tree), verbatim, on
  either opcode (dispatch.rs:999).

### Direct ORAM

- `0x60`: `[db_id u8][count u16][count × scripthash 20]`, or with explicit
  empty slots `[db_id u8][0xffff][count u16][count × present u8]
  [count × scripthash 20]`; count at most 256 (`encode_oram_lookup_request`,
  protocol.rs:1645) → `[db_id u8][count u16]`, per slot
  `[flags u8: 1 found, 2 whale][start_chunk_id u32][num_chunks u8][len u32]
  [chunk bytes]`, then zero bytes up to a size fixed by the database's
  public access budget and the slot count (`encode_oram_lookup_result`,
  protocol.rs:1734; `direct_oram_response_padding_bytes`, oram.rs:1026).

## Errors

`RESP_ERROR` (`0xff`) is `[len u32][UTF-8 message]` (`Response::encode`,
protocol.rs:936). The text is for people, except two prefixes clients act on:

- `insufficient gas: this frame needs N and the connection has M;`
  (credit_gate.rs:29): present credits, then resend.
- `free capacity busy` (`pir_credit::FREE_LANE_BUSY_PREFIX`): the
  best-effort lane is full; pay, wait, or go elsewhere.

An opcode the server does not serve gets `unsupported request 0x.. for
<role> role` (dispatch.rs:1102). A malformed body gets `RESP_ERROR`, except
for `0x05`, `0x11`, `0x21`, `0x33`, `0x41`, `0x43`, `0x51`, `0x52`, `0x53` and
`0x55`, which the server drops without a reply.

## Retired (reserved, never reuse)

These values once carried a message. `RETIRED_OPCODES` (protocol.rs:12)
lists them, and `crates/protocol/runtime/tests/opcode_registry.rs` fails if a
live opcode takes one or a decoder accepts one.

| Op | Former request / response | Removed in |
|---|---|---|
| `0x04` | `REQ_RESIDENCY` / `RESP_RESIDENCY`: mmap residency diagnostic | #42 |
| `0x08` | `REQ_CREDENTIAL_PRESENT` / `RESP_CREDENTIAL_OK`: ARC credential | #286 |
| `0x09` | `REQ_CASHU_BAT_PRESENT` / `RESP_CASHU_BAT_OK`: Cashu blind auth token | #286 |
| `0x0b` | `REQ_SESSION_GRANT_PRESENT` / `RESP_SESSION_GRANT_OK`: v1 session grant | #345, #346 |
| `0x0d` | `REQ_SERVICE_POLICY_V1` / `RESP_SERVICE_POLICY_V1`: Payment V1 signed service policy | #272, #273 |
| `0x0e` | `REQ_AUTH_BEGIN_V1` / `RESP_AUTH_RESULT_V1`: Payment V1 capability | #272, #273 |
| `0x0f` | `REQ_POW_CHALLENGE_V1` / `RESP_POW_CHALLENGE_V1`: proof-of-work admission | #270, #273 |
| `0x10` | `REQ_HARMONY_ATTACH_V1` / `RESP_HARMONY_ATTACH_V1`: Payment V1 HarmonyPIR half attach | #272, #273 |
| `0x30` | `REQ_REGISTER_KEYS` / `RESP_KEYS_ACK`: first OnionPIR key upload, now `0x50` | d261ff9f |
| `0x31` | `REQ_MERKLE_SIBLING_BATCH` / `RESP_MERKLE_SIBLING_BATCH`: global N-ary Merkle; earlier the first OnionPIR INDEX query | a1c4dc15 |
| `0x32` | `REQ_MERKLE_TREE_TOP` / `RESP_MERKLE_TREE_TOP`: global N-ary Merkle; earlier the first OnionPIR CHUNK query | a1c4dc15 |
| `0x42` | `REQ_HARMONY_QUERY` / `RESP_HARMONY_QUERY`: single HarmonyPIR query, superseded by `0x43` | #405 |
| `0x70` | `REQ_PIR2_SEALED_RECEIPT_GET` / `RESP_PIR2_SEALED_RECEIPT`: sealed-identity receipts | #397 |
| `0x80`–`0x85` | `REQ_ADMIN_AUTH_CHALLENGE`, `REQ_ADMIN_AUTH_RESPONSE`, `REQ_ADMIN_DB_UPLOAD_BEGIN`, `_CHUNK`, `_FINALIZE`, `REQ_ADMIN_DB_ACTIVATE`, each with its `RESP_`: admin database upload | #413, #414 |

Inside `REQ_CREDIT_PRESENT`, kind `2` (ARC presentations, #424) is retired
the same way.

## Stability policy (v1)

- An addition takes an unused value: not a live or retired opcode, and not
  `0xc7`, `0xfe` or `0xff`, which mark a chunk frame, a sealed record and an
  error.
- A changed request or response shape takes a new opcode, as the database
  proof did (`0x0a` bundle v1, `0x0c` bundle v2).
- A retired value stays reserved: it joins the table above and
  `RETIRED_OPCODES`, and is never assigned again.

The optional trailing fields that exist today (opt `db_id`, the seeds and
anchor after `tag_seed` in `0x01`/`0x40`, the `[0x01]` extension of the
catalog, the attestation PEMs) are part of the v1 shapes above.
