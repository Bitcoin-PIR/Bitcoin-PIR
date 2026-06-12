//! Minimal ChaCha20 block function (RFC 8439 state layout: 32-bit block
//! counter + 96-bit nonce).
//!
//! Implemented inline rather than via the RustCrypto `chacha20` crate so
//! that this consensus-adjacent code has zero feature-flag / API-drift
//! surface: MuHash3072 only ever needs the raw keystream of blocks
//! 0..6 under an all-zero nonce, exactly like Bitcoin Core's
//! `ChaCha20Aligned` (Core uses the djb 64-bit-nonce layout, but with a
//! zero nonce and counter < 2^32 the two layouts produce identical
//! state words, hence identical keystream).

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// One 64-byte keystream block for `key` / `nonce` at `counter`.
pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }

    let mut working = state;
    for _ in 0..10 {
        // column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.3.2 block function test vector.
    #[test]
    fn rfc8439_block_vector() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce: [u8; 12] =
            hex::decode("000000090000004a00000000").unwrap().try_into().unwrap();
        let block = chacha20_block(&key, &nonce, 1);
        assert_eq!(
            hex::encode(block),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }
}
