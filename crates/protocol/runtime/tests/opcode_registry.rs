//! Repository-level opcode collision guard.
//!
//! The runtime protocol and the independent service-protocol crate cannot
//! depend on each other merely to allocate constants.  This integration test
//! checks both directions against the runtime, unified-server JSON, OnionPIR,
//! and retired reservations.

use std::collections::BTreeMap;

use pir_runtime_core::protocol::*;

fn assert_unique(assignments: &[(&str, u8)]) {
    let mut seen = BTreeMap::new();
    for (name, opcode) in assignments {
        if let Some(previous) = seen.insert(*opcode, *name) {
            panic!(
                "opcode 0x{opcode:02x} is assigned to both {previous} and {name} in one direction"
            );
        }
    }
}

#[test]
fn request_opcode_registry_has_no_collisions() {
    assert_unique(&[
        ("PING", REQ_PING),
        ("GET_INFO", REQ_GET_INFO),
        ("GET_DB_CATALOG", REQ_GET_DB_CATALOG),
        // Implemented in unified_server rather than pir-runtime-core.
        ("GET_INFO_JSON", 0x03),
        ("RETIRED_MMAP_RESIDENCY", 0x04),
        ("ATTEST", REQ_ATTEST),
        ("HANDSHAKE", REQ_HANDSHAKE),
        ("ANNOUNCE", REQ_ANNOUNCE),
        ("LEGACY_ARC_PRESENT", REQ_CREDENTIAL_PRESENT),
        ("LEGACY_CASHU_BAT_PRESENT", REQ_CASHU_BAT_PRESENT),
        ("GET_DB_PROOF", REQ_GET_DB_PROOF),
        ("GET_DB_PROOF_V2", REQ_GET_DB_PROOF_V2),
        // Retired with the signed service-policy admission world (R3):
        // SERVICE_POLICY_V1, AUTH_BEGIN_V1, POW_CHALLENGE_V1,
        // HARMONY_ATTACH_V1. Never reassign.
        ("RETIRED_SERVICE_POLICY_V1", 0x0d),
        ("RETIRED_AUTH_BEGIN_V1", 0x0e),
        ("RETIRED_POW_CHALLENGE_V1", 0x0f),
        ("RETIRED_HARMONY_ATTACH_V1", 0x10),
        ("INDEX_BATCH", REQ_INDEX_BATCH),
        ("CHUNK_BATCH", REQ_CHUNK_BATCH),
        ("RETIRED_MERKLE_SIBLING_BATCH", 0x31),
        ("RETIRED_MERKLE_TREE_TOP", 0x32),
        ("BUCKET_MERKLE_SIB_BATCH", REQ_BUCKET_MERKLE_SIB_BATCH),
        ("BUCKET_MERKLE_TREE_TOPS", REQ_BUCKET_MERKLE_TREE_TOPS),
        ("HARMONY_GET_INFO", REQ_HARMONY_GET_INFO),
        ("HARMONY_HINTS", REQ_HARMONY_HINTS),
        ("HARMONY_QUERY", REQ_HARMONY_QUERY),
        ("HARMONY_BATCH_QUERY", REQ_HARMONY_BATCH_QUERY),
        ("HARMONY_HINTS_V2", REQ_HARMONY_HINTS_V2),
        ("HARMONY_HINTS_V2_HALF", REQ_HARMONY_HINTS_V2_HALF),
        // Implemented in apps/server/src/onionpir.rs.
        ("ONION_REGISTER_KEYS", 0x50),
        ("ONION_INDEX_QUERY", 0x51),
        ("ONION_CHUNK_QUERY", 0x52),
        ("ONION_MERKLE_INDEX_SIBLING", 0x53),
        ("ONION_MERKLE_INDEX_TREE_TOP", 0x54),
        ("ONION_MERKLE_DATA_SIBLING", 0x55),
        ("ONION_MERKLE_DATA_TREE_TOP", 0x56),
        ("ORAM_LOOKUP", REQ_ORAM_LOOKUP),
        ("ADMIN_AUTH_CHALLENGE", REQ_ADMIN_AUTH_CHALLENGE),
        ("ADMIN_AUTH_RESPONSE", REQ_ADMIN_AUTH_RESPONSE),
        ("ADMIN_DB_UPLOAD_BEGIN", REQ_ADMIN_DB_UPLOAD_BEGIN),
        ("ADMIN_DB_UPLOAD_CHUNK", REQ_ADMIN_DB_UPLOAD_CHUNK),
        ("ADMIN_DB_UPLOAD_FINALIZE", REQ_ADMIN_DB_UPLOAD_FINALIZE),
        ("ADMIN_DB_ACTIVATE", REQ_ADMIN_DB_ACTIVATE),
    ]);
}

#[test]
fn response_opcode_registry_has_no_collisions() {
    assert_unique(&[
        ("PONG", RESP_PONG),
        ("INFO", RESP_INFO),
        ("DB_CATALOG", RESP_DB_CATALOG),
        ("GET_INFO_JSON", 0x03),
        ("ATTEST", RESP_ATTEST),
        ("HANDSHAKE", RESP_HANDSHAKE),
        ("ANNOUNCE", RESP_ANNOUNCE),
        ("LEGACY_ARC_OK", RESP_CREDENTIAL_OK),
        ("LEGACY_CASHU_BAT_OK", RESP_CASHU_BAT_OK),
        ("DB_PROOF", RESP_DB_PROOF),
        ("DB_PROOF_V2", RESP_DB_PROOF_V2),
        ("RETIRED_SERVICE_POLICY_V1", 0x0d),
        ("RETIRED_AUTH_RESULT_V1", 0x0e),
        ("RETIRED_POW_CHALLENGE_V1", 0x0f),
        ("RETIRED_HARMONY_ATTACH_V1", 0x10),
        ("INDEX_BATCH", RESP_INDEX_BATCH),
        ("CHUNK_BATCH", RESP_CHUNK_BATCH),
        ("BUCKET_MERKLE_SIB_BATCH", RESP_BUCKET_MERKLE_SIB_BATCH),
        ("BUCKET_MERKLE_TREE_TOPS", RESP_BUCKET_MERKLE_TREE_TOPS),
        ("HARMONY_INFO", RESP_HARMONY_INFO),
        ("HARMONY_HINTS", RESP_HARMONY_HINTS),
        ("HARMONY_QUERY", RESP_HARMONY_QUERY),
        ("HARMONY_BATCH_QUERY", RESP_HARMONY_BATCH_QUERY),
        ("HARMONY_HINTS_KEY", RESP_HARMONY_HINTS_KEY),
        ("ONION_KEYS_ACK", 0x50),
        ("ONION_INDEX_RESULT", 0x51),
        ("ONION_CHUNK_RESULT", 0x52),
        ("ONION_MERKLE_INDEX_SIBLING", 0x53),
        ("ONION_MERKLE_INDEX_TREE_TOP", 0x54),
        ("ONION_MERKLE_DATA_SIBLING", 0x55),
        ("ONION_MERKLE_DATA_TREE_TOP", 0x56),
        ("ORAM_LOOKUP", RESP_ORAM_LOOKUP),
        ("ADMIN_AUTH_CHALLENGE", RESP_ADMIN_AUTH_CHALLENGE),
        ("ADMIN_AUTH_RESPONSE", RESP_ADMIN_AUTH_RESPONSE),
        ("ADMIN_DB_UPLOAD_BEGIN", RESP_ADMIN_DB_UPLOAD_BEGIN),
        ("ADMIN_DB_UPLOAD_CHUNK", RESP_ADMIN_DB_UPLOAD_CHUNK),
        ("ADMIN_DB_UPLOAD_FINALIZE", RESP_ADMIN_DB_UPLOAD_FINALIZE),
        ("ADMIN_DB_ACTIVATE", RESP_ADMIN_DB_ACTIVATE),
        ("ERROR", RESP_ERROR),
    ]);
}
