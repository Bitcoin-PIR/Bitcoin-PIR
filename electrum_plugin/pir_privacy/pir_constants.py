"""
Constants for the Batch PIR system.

Must match web/src/constants.ts and build/src/common.rs exactly.
"""

# ── Index-level constants ──────────────────────────────────────────────────

K = 75                          # Number of Batch PIR groups (index level)
NUM_HASHES = 3                  # Number of group assignments per entry
MASTER_SEED = 0x71a2ef38b4c90d15  # Master PRG seed for per-group cuckoo keys
INDEX_SLOTS_PER_BIN = 4         # Slots per cuckoo bin (index level)
INDEX_CUCKOO_NUM_HASHES = 2     # Number of cuckoo hash functions (index level)

SCRIPT_HASH_SIZE = 20           # bytes
TAG_SIZE = 8                    # Fingerprint tag size in bytes
INDEX_SLOT_SIZE = 17            # 8B tag + 4B start_chunk_id + 1B num_chunks + 4B tree_loc
INDEX_RESULT_SIZE = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE   # 68

# ── Chunk-level constants ──────────────────────────────────────────────────

K_CHUNK = 80                    # Number of Batch PIR groups for chunks
CHUNK_MASTER_SEED = 0xa3f7c2d918e4b065  # Master PRG seed for chunk-level cuckoo
CHUNK_SLOTS_PER_BIN = 3         # Slots per cuckoo bin (chunk level)
CHUNK_CUCKOO_NUM_HASHES = 2     # Number of cuckoo hash functions (chunk level)
CHUNK_SIZE = 40                 # Size of one chunk in bytes
CHUNKS_PER_UNIT = 1             # Consecutive chunks per PIR query unit
UNIT_DATA_SIZE = CHUNKS_PER_UNIT * CHUNK_SIZE  # 40
CHUNK_SLOT_SIZE = 4 + UNIT_DATA_SIZE  # 44 (4B chunk_id + data)
CHUNK_RESULT_SIZE = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE  # 132

# ── DPF ────────────────────────────────────────────────────────────────────

DPF_N = 20                      # DPF domain for index level: 2^20
CHUNK_DPF_N = 21                # DPF domain for chunk level: 2^21

# ── Protocol opcodes ───────────────────────────────────────────────────────

REQ_PING = 0x00
REQ_GET_INFO = 0x01
REQ_INDEX_BATCH = 0x11
REQ_CHUNK_BATCH = 0x21

RESP_PONG = 0x00
RESP_INFO = 0x01
RESP_INDEX_BATCH = 0x11
RESP_CHUNK_BATCH = 0x21
RESP_ERROR = 0xFF

# ── HarmonyPIR constants ──────────────────────────────────────────────────

HARMONY_INDEX_W = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE    # 68
HARMONY_CHUNK_W = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE  # 132
HARMONY_EMPTY = 0xFFFFFFFF

REQ_HARMONY_GET_INFO = 0x40
REQ_HARMONY_HINTS = 0x41
REQ_HARMONY_QUERY = 0x42
REQ_HARMONY_BATCH_QUERY = 0x43

RESP_HARMONY_INFO = 0x40
RESP_HARMONY_HINTS = 0x41
RESP_HARMONY_QUERY = 0x42
RESP_HARMONY_BATCH_QUERY = 0x43

# ── Default server URLs ───────────────────────────────────────────────────

DEFAULT_SERVER0_URL = 'ws://localhost:8091'
DEFAULT_SERVER1_URL = 'ws://localhost:8092'

# ── 64-bit mask ────────────────────────────────────────────────────────────

MASK64 = 0xFFFFFFFFFFFFFFFF
