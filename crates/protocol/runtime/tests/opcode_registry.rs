//! Locks the v1 opcode registry (docs/PROTOCOL.md): every live opcode keeps
//! its registered value, no value is taken twice in one direction, and no
//! live opcode takes a retired value.

use pir_runtime_core::protocol::*;

/// Request opcodes defined in this crate: `(constant, registered value)`.
const REQUESTS: &[(u8, u8)] = &[
    (REQ_PING, 0x00),
    (REQ_GET_INFO, 0x01),
    (REQ_GET_DB_CATALOG, 0x02),
    (REQ_ATTEST, 0x05),
    (REQ_HANDSHAKE, 0x06),
    (REQ_ANNOUNCE, 0x07),
    (REQ_GET_DB_PROOF, 0x0a),
    (REQ_GET_DB_PROOF_V2, 0x0c),
    (REQ_INDEX_BATCH, 0x11),
    (REQ_CREDIT_PRESENT, 0x12),
    (REQ_API_KEY, 0x13),
    (REQ_CHUNK_BATCH, 0x21),
    (REQ_BUCKET_MERKLE_SIB_BATCH, 0x33),
    (REQ_BUCKET_MERKLE_TREE_TOPS, 0x34),
    (REQ_HARMONY_GET_INFO, 0x40),
    (REQ_HARMONY_HINTS, 0x41),
    (REQ_HARMONY_BATCH_QUERY, 0x43),
    (REQ_HARMONY_HINTS_V2, 0x44),
    (REQ_HARMONY_HINTS_V2_HALF, 0x46),
    (REQ_ORAM_LOOKUP, 0x60),
];

/// Response opcodes defined in this crate: `(constant, registered value)`.
const RESPONSES: &[(u8, u8)] = &[
    (RESP_PONG, 0x00),
    (RESP_INFO, 0x01),
    (RESP_DB_CATALOG, 0x02),
    (RESP_ATTEST, 0x05),
    (RESP_HANDSHAKE, 0x06),
    (RESP_ANNOUNCE, 0x07),
    (RESP_DB_PROOF, 0x0a),
    (RESP_DB_PROOF_V2, 0x0c),
    (RESP_INDEX_BATCH, 0x11),
    (RESP_CREDIT_OK, 0x12),
    (RESP_API_KEY_OK, 0x13),
    (RESP_CHUNK_BATCH, 0x21),
    (RESP_BUCKET_MERKLE_SIB_BATCH, 0x33),
    (RESP_BUCKET_MERKLE_TREE_TOPS, 0x34),
    (RESP_HARMONY_INFO, 0x40),
    (RESP_HARMONY_HINTS, 0x41),
    (RESP_HARMONY_BATCH_QUERY, 0x43),
    (RESP_HARMONY_HINTS_KEY, 0x44),
    (RESP_ORAM_LOOKUP, 0x60),
    (RESP_ERROR, 0xff),
];

/// Values taken in both directions outside this crate: the JSON info opcode
/// (matched in apps/server/src/bin/unified_server/dispatch.rs), OnionPIR
/// (apps/server/src/onionpir.rs), and the first bytes of a chunk-envelope
/// frame (apps/server/src/bin/unified_server/io.rs) and of a sealed frame
/// (`ENCRYPTED_FRAME_MAGIC`).
const ELSEWHERE: &[u8] = &[0x03, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0xc7, 0xfe];

#[test]
fn live_opcodes_keep_their_values_and_stay_off_retired_ones() {
    for live in [REQUESTS, RESPONSES] {
        let mut taken = ELSEWHERE.to_vec();
        for &(opcode, registered) in live {
            assert_eq!(opcode, registered, "0x{registered:02x} changed");
            taken.push(opcode);
        }
        for (i, opcode) in taken.iter().enumerate() {
            assert!(!RETIRED_OPCODES.contains(opcode), "0x{opcode:02x} retired");
            assert!(!taken[..i].contains(opcode), "0x{opcode:02x} taken twice");
        }
    }
}

#[test]
fn decoders_treat_retired_opcodes_as_unknown() {
    for &opcode in RETIRED_OPCODES {
        let request = Request::decode(&[opcode]).unwrap_err().to_string();
        let response = Response::decode(&[opcode]).unwrap_err().to_string();
        assert!(request.starts_with("unknown request"), "{request}");
        assert!(response.starts_with("unknown response"), "{response}");
    }
}
