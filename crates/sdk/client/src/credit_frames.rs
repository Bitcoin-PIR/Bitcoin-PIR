//! Client-side classification of outgoing request frames for credits
//! (docs/CREDITS.md "Metering on the server"): the mirror of the server's
//! `metered_op_for_frame`, reading only the header fields a price depends
//! on. The server's classifier decodes every request in full; this one
//! must agree with it on every frame a client sends, which the server's
//! test suite checks against the real encoders.
//!
//! Also here: the response-size estimates a client pre-funds before a
//! metered frame, so a pipelined follow-up is never refused for egress the
//! server charges after the response.

use pir_credit::gas::{dpf_sibling_round, harmony_level, MeteredOp, TableKind};

// Request opcodes, mirroring `pir_runtime_core::protocol` and
// `runtime::onionpir`. Retired opcodes never appear here.
const REQ_INDEX_BATCH: u8 = 0x11;
const REQ_CHUNK_BATCH: u8 = 0x21;
const REQ_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
const REQ_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;
const REQ_HARMONY_HINTS: u8 = 0x41;
const REQ_HARMONY_QUERY: u8 = 0x42;
const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
const REQ_HARMONY_HINTS_V2: u8 = 0x44;
const REQ_HARMONY_HINTS_V2_HALF: u8 = 0x46;
const REQ_REGISTER_KEYS: u8 = 0x50;
const REQ_ONIONPIR_INDEX_QUERY: u8 = 0x51;
const REQ_ONIONPIR_CHUNK_QUERY: u8 = 0x52;
const REQ_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
const REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP: u8 = 0x54;
const REQ_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;
const REQ_ONIONPIR_MERKLE_DATA_TREE_TOP: u8 = 0x56;
const REQ_ORAM_LOOKUP: u8 = 0x60;

/// A little-endian cursor over a request body.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes(bytes.try_into().expect("two bytes")))
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(())
    }

    /// The optional trailing `db_id` byte every multi-database request
    /// appends only when it is not 0: exactly one byte left means that
    /// byte, none means database 0, anything else is not a frame the
    /// server would accept.
    fn trailing_db_id(&self) -> Option<u8> {
        match self.data.len() - self.pos {
            0 => Some(0),
            1 => Some(self.data[self.pos]),
            _ => None,
        }
    }
}

/// Skip `count` `[len u16][bytes]` items.
fn skip_u16_items(cursor: &mut Cursor<'_>, count: usize) -> Option<()> {
    for _ in 0..count {
        let len = usize::from(cursor.u16()?);
        cursor.skip(len)?;
    }
    Some(())
}

/// Skip `count` `[len u32][bytes]` items.
fn skip_u32_items(cursor: &mut Cursor<'_>, count: usize) -> Option<()> {
    for _ in 0..count {
        let len = usize::try_from(cursor.u32()?).ok()?;
        cursor.skip(len)?;
    }
    Some(())
}

/// The metered request kind and database of a complete outgoing frame
/// (`[len u32][variant][body]`, as `encode_request` builds it), `None` for
/// unmetered variants and for frames the server would not decode.
pub fn classify_frame(frame: &[u8]) -> Option<(MeteredOp, u8)> {
    if frame.len() < 5 {
        return None;
    }
    let declared = usize::try_from(u32::from_le_bytes(
        frame[..4].try_into().expect("four bytes"),
    ))
    .ok()?;
    if declared != frame.len() - 4 {
        return None;
    }
    classify_payload(frame[4], &frame[5..])
}

/// [`classify_frame`] for a variant byte and the body after it.
pub fn classify_payload(variant: u8, body: &[u8]) -> Option<(MeteredOp, u8)> {
    let mut cursor = Cursor::new(body);
    match variant {
        REQ_INDEX_BATCH | REQ_CHUNK_BATCH | REQ_BUCKET_MERKLE_SIB_BATCH => {
            let round_id = cursor.u16()?;
            let num_groups = usize::from(cursor.u8()?);
            let keys_per_group = usize::from(cursor.u8()?);
            skip_u16_items(&mut cursor, num_groups * keys_per_group)?;
            let db_id = cursor.trailing_db_id()?;
            let op = match variant {
                REQ_INDEX_BATCH => MeteredOp::DpfIndexRound,
                REQ_CHUNK_BATCH => MeteredOp::DpfChunkRound,
                _ => {
                    let (table, level) = dpf_sibling_round(round_id)?;
                    MeteredOp::DpfSiblingPass { table, level }
                }
            };
            Some((op, db_id))
        }
        REQ_BUCKET_MERKLE_TREE_TOPS => Some((MeteredOp::TreeTops, cursor.trailing_db_id()?)),
        REQ_HARMONY_HINTS => {
            cursor.skip(16)?; // prp_key
            cursor.u8()?; // prp_backend
            let level = cursor.u8()?;
            let num_groups = usize::from(cursor.u8()?);
            cursor.skip(num_groups)?;
            let db_id = cursor.trailing_db_id()?;
            harmony_level(level)?;
            Some((MeteredOp::HarmonyHintSet { level }, db_id))
        }
        REQ_HARMONY_HINTS_V2 => {
            cursor.u8()?; // level sentinel
            cursor.u8()?; // reserved
            Some((MeteredOp::HarmonyPoolEntry, cursor.trailing_db_id()?))
        }
        REQ_HARMONY_HINTS_V2_HALF => {
            cursor.skip(16)?; // session token
            cursor.u8()?; // side
            Some((MeteredOp::HarmonyContinuation, cursor.trailing_db_id()?))
        }
        REQ_HARMONY_QUERY => {
            let level = cursor.u8()?;
            cursor.u8()?; // group_id
            cursor.u16()?; // round_id
            let indices = usize::try_from(cursor.u32()?).ok()?;
            cursor.skip(indices.checked_mul(4)?)?;
            let db_id = cursor.trailing_db_id()?;
            harmony_level(level)?;
            Some((
                MeteredOp::HarmonyQuery {
                    level,
                    sub_queries: 1,
                },
                db_id,
            ))
        }
        REQ_HARMONY_BATCH_QUERY => {
            let level = cursor.u8()?;
            cursor.u16()?; // round_id
            let items = usize::from(cursor.u16()?);
            let sub_queries = cursor.u8()?;
            for _ in 0..items {
                cursor.u8()?; // group_id
                for _ in 0..sub_queries {
                    let indices = usize::try_from(cursor.u32()?).ok()?;
                    cursor.skip(indices.checked_mul(4)?)?;
                }
            }
            let db_id = cursor.trailing_db_id()?;
            harmony_level(level)?;
            Some((
                MeteredOp::HarmonyQuery {
                    level,
                    sub_queries: u32::from(sub_queries),
                },
                db_id,
            ))
        }
        REQ_ORAM_LOOKUP => Some((MeteredOp::OramLookup, cursor.u8()?)),
        REQ_REGISTER_KEYS => {
            skip_u32_items(&mut cursor, 2)?; // galois keys, gsw keys
            Some((MeteredOp::OnionRegisterKeys, cursor.trailing_db_id()?))
        }
        REQ_ONIONPIR_INDEX_QUERY
        | REQ_ONIONPIR_CHUNK_QUERY
        | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
        | REQ_ONIONPIR_MERKLE_DATA_SIBLING => {
            cursor.u16()?; // round_id
            let queries = usize::from(cursor.u8()?);
            skip_u32_items(&mut cursor, queries)?;
            let db_id = cursor.trailing_db_id()?;
            let op = match variant {
                REQ_ONIONPIR_INDEX_QUERY => MeteredOp::OnionIndexQuery,
                REQ_ONIONPIR_CHUNK_QUERY => MeteredOp::OnionChunkQuery,
                REQ_ONIONPIR_MERKLE_INDEX_SIBLING => MeteredOp::OnionSiblingQuery {
                    table: TableKind::Index,
                },
                _ => MeteredOp::OnionSiblingQuery {
                    table: TableKind::Chunk,
                },
            };
            Some((op, db_id))
        }
        REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP => {
            Some((MeteredOp::OnionTreeTops, cursor.trailing_db_id()?))
        }
        _ => None,
    }
}

/// Response bytes a client pre-funds for `op` before sending it, so the
/// egress the server charges after the response never leaves a pipelined
/// follow-up refused. Sized from the checkpoint-948454 corpora
/// (docs/CREDITS.md "Measurements") with headroom; a connection replaces
/// them with what it observed once a response of the same kind arrived.
pub fn expected_response_bytes(op: MeteredOp) -> u64 {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    match op {
        MeteredOp::DpfIndexRound => 16 * KB,
        MeteredOp::DpfChunkRound => 32 * KB,
        MeteredOp::DpfSiblingPass { .. } => 32 * KB,
        MeteredOp::TreeTops => 12 * MB,
        MeteredOp::OnionRegisterKeys => KB,
        MeteredOp::OnionIndexQuery => 2 * MB,
        MeteredOp::OnionChunkQuery => MB,
        MeteredOp::OnionSiblingQuery { .. } => MB,
        MeteredOp::OnionTreeTops => 2 * MB,
        MeteredOp::HarmonyPoolEntry => 20 * MB,
        MeteredOp::HarmonyContinuation => 16 * MB,
        MeteredOp::HarmonyHintSet { level } | MeteredOp::HarmonyQuery { level, .. } => {
            match harmony_level(level) {
                Some((TableKind::Index, None)) => 5 * MB,
                Some((TableKind::Chunk, None)) => 16 * MB,
                Some((TableKind::Index, Some(sibling))) => {
                    [8 * MB, 3 * MB, MB, MB][sibling.min(3) as usize]
                }
                Some((TableKind::Chunk, Some(sibling))) => {
                    [12 * MB, 4 * MB, 2 * MB, 2 * MB][sibling.min(3) as usize]
                }
                None => 16 * MB,
            }
        }
        MeteredOp::OramLookup => 64 * KB,
    }
}

/// A stable key for "responses of this kind", used to remember observed
/// response sizes per connection.
pub(crate) fn op_family(op: MeteredOp) -> u32 {
    match op {
        MeteredOp::DpfIndexRound => 0x11,
        MeteredOp::DpfChunkRound => 0x21,
        MeteredOp::DpfSiblingPass { table, level } => {
            0x3300 + table_code(table) * 0x10 + u32::from(level)
        }
        MeteredOp::TreeTops => 0x34,
        MeteredOp::OnionRegisterKeys => 0x50,
        MeteredOp::OnionIndexQuery => 0x51,
        MeteredOp::OnionChunkQuery => 0x52,
        MeteredOp::OnionSiblingQuery { table } => 0x5300 + table_code(table),
        MeteredOp::OnionTreeTops => 0x54,
        MeteredOp::HarmonyPoolEntry => 0x44,
        MeteredOp::HarmonyContinuation => 0x46,
        MeteredOp::HarmonyHintSet { level } => 0x4100 + u32::from(level),
        MeteredOp::HarmonyQuery { level, .. } => 0x4200 + u32::from(level),
        MeteredOp::OramLookup => 0x60,
    }
}

fn table_code(table: TableKind) -> u32 {
    match table {
        TableKind::Index => 0,
        TableKind::Chunk => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(variant: u8, body: &[u8]) -> Vec<u8> {
        crate::protocol::encode_request(variant, body)
    }

    fn batch_body(round_id: u16, groups: u8, keys_per_group: u8, db_id: u8) -> Vec<u8> {
        let mut body = round_id.to_le_bytes().to_vec();
        body.push(groups);
        body.push(keys_per_group);
        for _ in 0..u16::from(groups) * u16::from(keys_per_group) {
            body.extend_from_slice(&3u16.to_le_bytes());
            body.extend_from_slice(&[7, 8, 9]);
        }
        if db_id != 0 {
            body.push(db_id);
        }
        body
    }

    #[test]
    fn dpf_frames() {
        assert_eq!(
            classify_frame(&frame(REQ_INDEX_BATCH, &batch_body(0, 75, 2, 0))),
            Some((MeteredOp::DpfIndexRound, 0))
        );
        assert_eq!(
            classify_frame(&frame(REQ_CHUNK_BATCH, &batch_body(4, 80, 3, 1))),
            Some((MeteredOp::DpfChunkRound, 1))
        );
        assert_eq!(
            classify_frame(&frame(
                REQ_BUCKET_MERKLE_SIB_BATCH,
                &batch_body(102, 25, 1, 0)
            )),
            Some((
                MeteredOp::DpfSiblingPass {
                    table: TableKind::Chunk,
                    level: 2
                },
                0
            ))
        );
        // An unknown sibling table code is not priced.
        assert_eq!(
            classify_frame(&frame(
                REQ_BUCKET_MERKLE_SIB_BATCH,
                &batch_body(200, 25, 1, 0)
            )),
            None
        );
        assert_eq!(
            classify_frame(&frame(REQ_BUCKET_MERKLE_TREE_TOPS, &[])),
            Some((MeteredOp::TreeTops, 0))
        );
        assert_eq!(
            classify_frame(&frame(REQ_BUCKET_MERKLE_TREE_TOPS, &[2])),
            Some((MeteredOp::TreeTops, 2))
        );
        // Truncated keys or two trailing bytes: not a frame the server takes.
        let mut short = batch_body(0, 2, 2, 0);
        short.truncate(short.len() - 2);
        assert_eq!(classify_frame(&frame(REQ_INDEX_BATCH, &short)), None);
        let mut long = batch_body(0, 2, 2, 0);
        long.extend_from_slice(&[1, 1]);
        assert_eq!(classify_frame(&frame(REQ_INDEX_BATCH, &long)), None);
    }

    #[test]
    fn harmony_and_oram_frames() {
        let mut hints = vec![0xaa; 16];
        hints.push(1);
        hints.push(21);
        hints.push(2);
        hints.extend_from_slice(&[0, 1]);
        assert_eq!(
            classify_frame(&frame(REQ_HARMONY_HINTS, &hints)),
            Some((MeteredOp::HarmonyHintSet { level: 21 }, 0))
        );
        hints[17] = 7; // a level that is not a table
        assert_eq!(classify_frame(&frame(REQ_HARMONY_HINTS, &hints)), None);
        assert_eq!(
            classify_frame(&frame(REQ_HARMONY_HINTS_V2, &[0xff, 0x00, 3])),
            Some((MeteredOp::HarmonyPoolEntry, 3))
        );
        let mut half = vec![0x11; 16];
        half.push(1);
        assert_eq!(
            classify_frame(&frame(REQ_HARMONY_HINTS_V2_HALF, &half)),
            Some((MeteredOp::HarmonyContinuation, 0))
        );
        let mut query = vec![1u8, 4];
        query.extend_from_slice(&0u16.to_le_bytes());
        query.extend_from_slice(&2u32.to_le_bytes());
        query.extend_from_slice(&5u32.to_le_bytes());
        query.extend_from_slice(&6u32.to_le_bytes());
        assert_eq!(
            classify_frame(&frame(REQ_HARMONY_QUERY, &query)),
            Some((
                MeteredOp::HarmonyQuery {
                    level: 1,
                    sub_queries: 1
                },
                0
            ))
        );
        let mut batch = vec![10u8];
        batch.extend_from_slice(&3u16.to_le_bytes());
        batch.extend_from_slice(&2u16.to_le_bytes());
        batch.push(2);
        for group in [0u8, 1] {
            batch.push(group);
            for _ in 0..2 {
                batch.extend_from_slice(&1u32.to_le_bytes());
                batch.extend_from_slice(&9u32.to_le_bytes());
            }
        }
        batch.push(1);
        assert_eq!(
            classify_frame(&frame(REQ_HARMONY_BATCH_QUERY, &batch)),
            Some((
                MeteredOp::HarmonyQuery {
                    level: 10,
                    sub_queries: 2
                },
                1
            ))
        );
        let mut oram = vec![1u8];
        oram.extend_from_slice(&1u16.to_le_bytes());
        oram.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            classify_frame(&frame(REQ_ORAM_LOOKUP, &oram)),
            Some((MeteredOp::OramLookup, 1))
        );
    }

    #[test]
    fn onion_frames_and_unmetered_variants() {
        let mut keys = 2u32.to_le_bytes().to_vec();
        keys.extend_from_slice(&[1, 2]);
        keys.extend_from_slice(&1u32.to_le_bytes());
        keys.push(3);
        keys.push(1);
        assert_eq!(
            classify_frame(&frame(REQ_REGISTER_KEYS, &keys)),
            Some((MeteredOp::OnionRegisterKeys, 1))
        );
        let mut query = 0u16.to_le_bytes().to_vec();
        query.push(2);
        for _ in 0..2 {
            query.extend_from_slice(&4u32.to_le_bytes());
            query.extend_from_slice(&[0; 4]);
        }
        assert_eq!(
            classify_frame(&frame(REQ_ONIONPIR_CHUNK_QUERY, &query)),
            Some((MeteredOp::OnionChunkQuery, 0))
        );
        assert_eq!(
            classify_frame(&frame(REQ_ONIONPIR_MERKLE_DATA_SIBLING, &query)),
            Some((
                MeteredOp::OnionSiblingQuery {
                    table: TableKind::Chunk
                },
                0
            ))
        );
        assert_eq!(
            classify_frame(&frame(REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, &[])),
            Some((MeteredOp::OnionTreeTops, 0))
        );
        for unmetered in [
            0x00u8, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x12, 0x40, 0x70, 0x80,
        ] {
            assert_eq!(
                classify_frame(&frame(unmetered, &[1, 2, 3])),
                None,
                "0x{unmetered:02x}"
            );
        }
        // A frame whose length prefix disagrees with its length is not classified.
        let mut bad = frame(REQ_BUCKET_MERKLE_TREE_TOPS, &[]);
        bad.push(0);
        assert_eq!(classify_frame(&bad), None);
        assert_eq!(classify_frame(&[]), None);
    }

    #[test]
    fn response_estimates_cover_the_corpora() {
        assert!(expected_response_bytes(MeteredOp::TreeTops) > 9_155_389);
        assert!(expected_response_bytes(MeteredOp::HarmonyPoolEntry) > 15_440_184 + 4_149_986);
        assert!(
            expected_response_bytes(MeteredOp::HarmonyQuery {
                level: 1,
                sub_queries: 1
            }) > 15_418_011
        );
        assert!(
            expected_response_bytes(MeteredOp::HarmonyQuery {
                level: 20,
                sub_queries: 1
            }) > 10_547_611
        );
        assert!(expected_response_bytes(MeteredOp::HarmonyHintSet { level: 10 }) > 7_219_586);
        assert!(expected_response_bytes(MeteredOp::OnionIndexQuery) > 1_690_208);
        assert!(
            expected_response_bytes(MeteredOp::DpfSiblingPass {
                table: TableKind::Chunk,
                level: 0
            }) > 20_649
        );
        assert_ne!(
            op_family(MeteredOp::HarmonyHintSet { level: 10 }),
            op_family(MeteredOp::HarmonyQuery {
                level: 10,
                sub_queries: 1
            })
        );
    }
}
