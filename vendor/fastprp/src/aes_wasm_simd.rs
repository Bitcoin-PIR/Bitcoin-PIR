//! WASM SIMD AES-128 encryption using the fixsliced representation.
//!
//! Port of the fixslice32 algorithm from the RustCrypto `aes` crate (v0.8.4),
//! widened from `u32` to `v128` (4 × u32 lanes = 8 blocks in parallel).
//!
//! Reference: <https://eprint.iacr.org/2020/1123.pdf>
//! Original author: Alexandre Adomnicai (NTU Singapore), MIT/Apache-2.0.
//!
//! Only the encrypt direction is implemented (no decrypt needed for PRF use).

#![allow(clippy::unreadable_literal, clippy::too_many_arguments)]

use aes::Block;
use core::arch::wasm32::*;

// ============================================================================
// SIMD helpers
// ============================================================================

#[inline(always)]
fn v_xor(a: v128, b: v128) -> v128 {
    v128_xor(a, b)
}
#[inline(always)]
fn v_and(a: v128, b: v128) -> v128 {
    v128_and(a, b)
}
#[inline(always)]
fn v_or(a: v128, b: v128) -> v128 {
    v128_or(a, b)
}
#[inline(always)]
fn v_shr(a: v128, n: u32) -> v128 {
    u32x4_shr(a, n)
}
#[inline(always)]
fn v_shl(a: v128, n: u32) -> v128 {
    u32x4_shl(a, n)
}
#[inline(always)]
fn v_splat(c: u32) -> v128 {
    u32x4_splat(c)
}

/// Rotate right each 32-bit lane by `n` bits.
#[inline(always)]
fn v_ror(x: v128, n: u32) -> v128 {
    v_or(v_shr(x, n), v_shl(x, 32 - n))
}

#[inline(always)]
fn v_new(a: u32, b: u32, c: u32, d: u32) -> v128 {
    u32x4(a, b, c, d)
}

fn v_extract_lane(v: v128, lane: usize) -> u32 {
    match lane {
        0 => u32x4_extract_lane::<0>(v),
        1 => u32x4_extract_lane::<1>(v),
        2 => u32x4_extract_lane::<2>(v),
        _ => u32x4_extract_lane::<3>(v),
    }
}

// ============================================================================
// Types
// ============================================================================

type SimdState = [v128; 8];
type SimdRoundKeys = [v128; 88];

// ============================================================================
// Scalar key schedule (from fixslice32.rs, runs once at init)
// ============================================================================


#[inline(always)]
fn ror(x: u32, y: u32) -> u32 {
    x.rotate_right(y)
}

#[inline(always)]
fn ror_distance(rows: u32, cols: u32) -> u32 {
    (rows << 3) + (cols << 1)
}

#[inline]
fn s_delta_swap_1(a: &mut u32, shift: u32, mask: u32) {
    let t = (*a ^ ((*a) >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

#[inline]
fn s_delta_swap_2(a: &mut u32, b: &mut u32, shift: u32, mask: u32) {
    let t = (*a ^ ((*b) >> shift)) & mask;
    *a ^= t;
    *b ^= t << shift;
}

fn s_shift_rows_1(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        s_delta_swap_1(x, 4, 0x0c0f0300);
        s_delta_swap_1(x, 2, 0x33003300);
    }
}

fn s_shift_rows_2(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        s_delta_swap_1(x, 4, 0x0f000f00);
    }
}

fn s_shift_rows_3(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        s_delta_swap_1(x, 4, 0x030f0c00);
        s_delta_swap_1(x, 2, 0x33003300);
    }
}

#[inline(always)]
fn s_inv_shift_rows_1(state: &mut [u32]) {
    s_shift_rows_3(state);
}
#[inline(always)]
fn s_inv_shift_rows_2(state: &mut [u32]) {
    s_shift_rows_2(state);
}
#[inline(always)]
fn s_inv_shift_rows_3(state: &mut [u32]) {
    s_shift_rows_1(state);
}

#[inline(always)]
fn s_add_round_constant_bit(state: &mut [u32], bit: usize) {
    state[bit] ^= 0x0000c000;
}

fn s_memshift32(buffer: &mut [u32], src_offset: usize) {
    debug_assert_eq!(src_offset % 8, 0);
    let dst_offset = src_offset + 8;
    debug_assert!(dst_offset + 8 <= buffer.len());
    for i in (0..8).rev() {
        buffer[dst_offset + i] = buffer[src_offset + i];
    }
}

fn s_xor_columns(rkeys: &mut [u32], offset: usize, idx_xor: usize, idx_ror: u32) {
    for i in 0..8 {
        let off_i = offset + i;
        let rk = rkeys[off_i - idx_xor] ^ (0x03030303 & ror(rkeys[off_i], idx_ror));
        rkeys[off_i] =
            rk ^ (0xfcfcfcfc & (rk << 2)) ^ (0xf0f0f0f0 & (rk << 4)) ^ (0xc0c0c0c0 & (rk << 6));
    }
}

fn s_bitslice(output: &mut [u32], input0: &[u8], input1: &[u8]) {
    debug_assert_eq!(output.len(), 8);
    debug_assert_eq!(input0.len(), 16);
    debug_assert_eq!(input1.len(), 16);

    let mut t0 = u32::from_le_bytes(input0[0x00..0x04].try_into().unwrap());
    let mut t2 = u32::from_le_bytes(input0[0x04..0x08].try_into().unwrap());
    let mut t4 = u32::from_le_bytes(input0[0x08..0x0c].try_into().unwrap());
    let mut t6 = u32::from_le_bytes(input0[0x0c..0x10].try_into().unwrap());
    let mut t1 = u32::from_le_bytes(input1[0x00..0x04].try_into().unwrap());
    let mut t3 = u32::from_le_bytes(input1[0x04..0x08].try_into().unwrap());
    let mut t5 = u32::from_le_bytes(input1[0x08..0x0c].try_into().unwrap());
    let mut t7 = u32::from_le_bytes(input1[0x0c..0x10].try_into().unwrap());

    let m0 = 0x55555555;
    s_delta_swap_2(&mut t1, &mut t0, 1, m0);
    s_delta_swap_2(&mut t3, &mut t2, 1, m0);
    s_delta_swap_2(&mut t5, &mut t4, 1, m0);
    s_delta_swap_2(&mut t7, &mut t6, 1, m0);

    let m1 = 0x33333333;
    s_delta_swap_2(&mut t2, &mut t0, 2, m1);
    s_delta_swap_2(&mut t3, &mut t1, 2, m1);
    s_delta_swap_2(&mut t6, &mut t4, 2, m1);
    s_delta_swap_2(&mut t7, &mut t5, 2, m1);

    let m2 = 0x0f0f0f0f;
    s_delta_swap_2(&mut t4, &mut t0, 4, m2);
    s_delta_swap_2(&mut t5, &mut t1, 4, m2);
    s_delta_swap_2(&mut t6, &mut t2, 4, m2);
    s_delta_swap_2(&mut t7, &mut t3, 4, m2);

    output[0] = t0;
    output[1] = t1;
    output[2] = t2;
    output[3] = t3;
    output[4] = t4;
    output[5] = t5;
    output[6] = t6;
    output[7] = t7;
}

/// Scalar sub_bytes_nots: NOT on 4 specific state words.
fn s_sub_bytes_nots(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    state[0] ^= 0xffffffff;
    state[1] ^= 0xffffffff;
    state[5] ^= 0xffffffff;
    state[6] ^= 0xffffffff;
}

/// Scalar sub_bytes (Boyar-Peralta S-box in bitsliced form).
#[rustfmt::skip]
fn s_sub_bytes(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);

    let u7 = state[0]; let u6 = state[1]; let u5 = state[2]; let u4 = state[3];
    let u3 = state[4]; let u2 = state[5]; let u1 = state[6]; let u0 = state[7];

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;
    let t2 = y12 & y15;
    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;
    let y9 = u0 ^ u3;
    let y11 = y20 ^ y9;
    let t12 = y9 & y11;
    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;
    let y17 = y10 ^ y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let y19 = y10 ^ y8;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let t7 = y13 & y16;
    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t18 = t6 ^ t16;
    let t22 = t18 ^ y19;
    let y2 = y1 ^ u0;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t20 = t11 ^ t16;
    let t24 = t20 ^ y18;
    let y5 = y1 ^ u6;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t19 = t9 ^ t14;
    let t23 = t19 ^ y21;
    let y3 = y5 ^ y8;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let z14 = t29 & y2;
    let z5 = t29 & y7;
    let t30 = t23 ^ t24;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t43 = t29 ^ t40;
    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;
    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;
    let z0 = t44 & y15;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;
    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;
    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;
    let z16 = t45 & y14;
    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;
    let z15 = t42 & y9;
    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;
    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;
    let tc13 = z13 ^ tc1;
    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;
    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;
    let s2 = tc26 ^ z17;
    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    state[0] = s7; state[1] = s6; state[2] = s5; state[3] = s4;
    state[4] = s3; state[5] = s2; state[6] = s1; state[7] = s0;
}

/// AES-128 key schedule in fixsliced representation (scalar).
fn aes128_key_schedule(key: &[u8; 16]) -> [u32; 88] {
    let mut rkeys = [0u32; 88];

    s_bitslice(&mut rkeys[..8], key, key);

    let mut rk_off = 0;
    for rcon in 0..10 {
        s_memshift32(&mut rkeys, rk_off);
        rk_off += 8;

        s_sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        s_sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        if rcon < 8 {
            s_add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon);
        } else {
            s_add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 8);
            s_add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 7);
            s_add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 5);
            s_add_round_constant_bit(&mut rkeys[rk_off..(rk_off + 8)], rcon - 4);
        }

        s_xor_columns(&mut rkeys, rk_off, 8, ror_distance(1, 3));
    }

    // Adjust to match fixslicing format (non-compact path)
    for i in (8..72).step_by(32) {
        s_inv_shift_rows_1(&mut rkeys[i..(i + 8)]);
        s_inv_shift_rows_2(&mut rkeys[(i + 8)..(i + 16)]);
        s_inv_shift_rows_3(&mut rkeys[(i + 16)..(i + 24)]);
    }
    s_inv_shift_rows_1(&mut rkeys[72..80]);

    // Account for NOTs removed from sub_bytes
    for i in 1..11 {
        s_sub_bytes_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Splat each scalar round key u32 to v128 (same value in all 4 lanes).
fn splat_round_keys(scalar: &[u32; 88]) -> SimdRoundKeys {
    let mut simd = [v_splat(0); 88];
    for i in 0..88 {
        simd[i] = v_splat(scalar[i]);
    }
    simd
}

// ============================================================================
// SIMD encryption primitives (fixslice32 widened to v128)
// ============================================================================

#[inline]
fn v_delta_swap_1(a: &mut v128, shift: u32, mask: v128) {
    let t = v_and(v_xor(*a, v_shr(*a, shift)), mask);
    *a = v_xor(*a, v_xor(t, v_shl(t, shift)));
}

/// delta_swap_2 on two elements of an array (avoids double-mutable-borrow).
#[inline]
fn v_delta_swap_2_arr(state: &mut [v128], i: usize, j: usize, shift: u32, mask: v128) {
    let t = v_and(v_xor(state[i], v_shr(state[j], shift)), mask);
    state[i] = v_xor(state[i], t);
    state[j] = v_xor(state[j], v_shl(t, shift));
}

/// SIMD sub_bytes (Boyar-Peralta S-box, widened from u32 to v128).
#[rustfmt::skip]
fn v_sub_bytes(state: &mut SimdState) {
    let u7 = state[0]; let u6 = state[1]; let u5 = state[2]; let u4 = state[3];
    let u3 = state[4]; let u2 = state[5]; let u1 = state[6]; let u0 = state[7];

    let y14 = v_xor(u3, u5);
    let y13 = v_xor(u0, u6);
    let y12 = v_xor(y13, y14);
    let t1 = v_xor(u4, y12);
    let y15 = v_xor(t1, u5);
    let t2 = v_and(y12, y15);
    let y6 = v_xor(y15, u7);
    let y20 = v_xor(t1, u1);
    let y9 = v_xor(u0, u3);
    let y11 = v_xor(y20, y9);
    let t12 = v_and(y9, y11);
    let y7 = v_xor(u7, y11);
    let y8 = v_xor(u0, u5);
    let t0 = v_xor(u1, u2);
    let y10 = v_xor(y15, t0);
    let y17 = v_xor(y10, y11);
    let t13 = v_and(y14, y17);
    let t14 = v_xor(t13, t12);
    let y19 = v_xor(y10, y8);
    let t15 = v_and(y8, y10);
    let t16 = v_xor(t15, t12);
    let y16 = v_xor(t0, y11);
    let y21 = v_xor(y13, y16);
    let t7 = v_and(y13, y16);
    let y18 = v_xor(u0, y16);
    let y1 = v_xor(t0, u7);
    let y4 = v_xor(y1, u3);
    let t5 = v_and(y4, u7);
    let t6 = v_xor(t5, t2);
    let t18 = v_xor(t6, t16);
    let t22 = v_xor(t18, y19);
    let y2 = v_xor(y1, u0);
    let t10 = v_and(y2, y7);
    let t11 = v_xor(t10, t7);
    let t20 = v_xor(t11, t16);
    let t24 = v_xor(t20, y18);
    let y5 = v_xor(y1, u6);
    let t8 = v_and(y5, y1);
    let t9 = v_xor(t8, t7);
    let t19 = v_xor(t9, t14);
    let t23 = v_xor(t19, y21);
    let y3 = v_xor(y5, y8);
    let t3 = v_and(y3, y6);
    let t4 = v_xor(t3, t2);
    let t17 = v_xor(t4, y20);
    let t21 = v_xor(t17, t14);
    let t26 = v_and(t21, t23);
    let t27 = v_xor(t24, t26);
    let t31 = v_xor(t22, t26);
    let t25 = v_xor(t21, t22);
    let t28 = v_and(t25, t27);
    let t29 = v_xor(t28, t22);
    let z14 = v_and(t29, y2);
    let z5 = v_and(t29, y7);
    let t30 = v_xor(t23, t24);
    let t32 = v_and(t31, t30);
    let t33 = v_xor(t32, t24);
    let t35 = v_xor(t27, t33);
    let t36 = v_and(t24, t35);
    let t38 = v_xor(t27, t36);
    let t39 = v_and(t29, t38);
    let t40 = v_xor(t25, t39);
    let t43 = v_xor(t29, t40);
    let z3 = v_and(t43, y16);
    let tc12 = v_xor(z3, z5);
    let z12 = v_and(t43, y13);
    let z13 = v_and(t40, y5);
    let z4 = v_and(t40, y1);
    let tc6 = v_xor(z3, z4);
    let t34 = v_xor(t23, t33);
    let t37 = v_xor(t36, t34);
    let t41 = v_xor(t40, t37);
    let z8 = v_and(t41, y10);
    let z17 = v_and(t41, y8);
    let t44 = v_xor(t33, t37);
    let z0 = v_and(t44, y15);
    let z9 = v_and(t44, y12);
    let z10 = v_and(t37, y3);
    let z1 = v_and(t37, y6);
    let tc5 = v_xor(z1, z0);
    let tc11 = v_xor(tc6, tc5);
    let z11 = v_and(t33, y4);
    let t42 = v_xor(t29, t33);
    let t45 = v_xor(t42, t41);
    let z7 = v_and(t45, y17);
    let tc8 = v_xor(z7, tc6);
    let z16 = v_and(t45, y14);
    let z6 = v_and(t42, y11);
    let tc16 = v_xor(z6, tc8);
    let z15 = v_and(t42, y9);
    let tc20 = v_xor(z15, tc16);
    let tc1 = v_xor(z15, z16);
    let tc2 = v_xor(z10, tc1);
    let tc21 = v_xor(tc2, z11);
    let tc3 = v_xor(z9, tc2);
    let s0 = v_xor(tc3, tc16);
    let s3 = v_xor(tc3, tc11);
    let s1 = v_xor(s3, tc16);
    let tc13 = v_xor(z13, tc1);
    let z2 = v_and(t33, u7);
    let tc4 = v_xor(z0, z2);
    let tc7 = v_xor(z12, tc4);
    let tc9 = v_xor(z8, tc7);
    let tc10 = v_xor(tc8, tc9);
    let tc17 = v_xor(z14, tc10);
    let s5 = v_xor(tc21, tc17);
    let tc26 = v_xor(tc17, tc20);
    let s2 = v_xor(tc26, z17);
    let tc14 = v_xor(tc4, tc12);
    let tc18 = v_xor(tc13, tc14);
    let s6 = v_xor(tc10, tc18);
    let s7 = v_xor(z12, tc18);
    let s4 = v_xor(tc14, s3);

    state[0] = s7; state[1] = s6; state[2] = s5; state[3] = s4;
    state[4] = s3; state[5] = s2; state[6] = s1; state[7] = s0;
}

/// SIMD add_round_key: XOR 8 state words with round key words.
#[inline]
fn v_add_round_key(state: &mut SimdState, rkey: &[v128]) {
    debug_assert!(rkey.len() >= 8);
    for i in 0..8 {
        state[i] = v_xor(state[i], rkey[i]);
    }
}

/// SIMD shift_rows_2 (used once in encryption, non-compact path).
fn v_shift_rows_2(state: &mut SimdState) {
    let m = v_splat(0x0f000f00);
    for x in state.iter_mut() {
        v_delta_swap_1(x, 4, m);
    }
}

// --- Rotation helpers (v128 versions) ---

#[inline(always)]
fn v_rotate_rows_1(x: v128) -> v128 {
    v_ror(x, ror_distance(1, 0))
}

#[inline(always)]
fn v_rotate_rows_2(x: v128) -> v128 {
    v_ror(x, ror_distance(2, 0))
}

#[inline(always)]
fn v_rotate_rows_and_columns_1_1(x: v128) -> v128 {
    v_or(
        v_and(v_ror(x, ror_distance(1, 1)), v_splat(0x3f3f3f3f)),
        v_and(v_ror(x, ror_distance(0, 1)), v_splat(0xc0c0c0c0)),
    )
}

#[inline(always)]
fn v_rotate_rows_and_columns_1_2(x: v128) -> v128 {
    v_or(
        v_and(v_ror(x, ror_distance(1, 2)), v_splat(0x0f0f0f0f)),
        v_and(v_ror(x, ror_distance(0, 2)), v_splat(0xf0f0f0f0)),
    )
}

#[inline(always)]
fn v_rotate_rows_and_columns_1_3(x: v128) -> v128 {
    v_or(
        v_and(v_ror(x, ror_distance(1, 3)), v_splat(0x03030303)),
        v_and(v_ror(x, ror_distance(0, 3)), v_splat(0xfcfcfcfc)),
    )
}

#[inline(always)]
fn v_rotate_rows_and_columns_2_2(x: v128) -> v128 {
    v_or(
        v_and(v_ror(x, ror_distance(2, 2)), v_splat(0x0f0f0f0f)),
        v_and(v_ror(x, ror_distance(1, 2)), v_splat(0xf0f0f0f0)),
    )
}

// --- MixColumns (v128 versions, forward only) ---

macro_rules! define_v_mix_columns {
    ($name:ident, $first_rotate:path, $second_rotate:path) => {
        #[rustfmt::skip]
        fn $name(state: &mut SimdState) {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = (
                state[0], state[1], state[2], state[3],
                state[4], state[5], state[6], state[7],
            );
            let (b0, b1, b2, b3, b4, b5, b6, b7) = (
                $first_rotate(a0), $first_rotate(a1),
                $first_rotate(a2), $first_rotate(a3),
                $first_rotate(a4), $first_rotate(a5),
                $first_rotate(a6), $first_rotate(a7),
            );
            let (c0, c1, c2, c3, c4, c5, c6, c7) = (
                v_xor(a0, b0), v_xor(a1, b1), v_xor(a2, b2), v_xor(a3, b3),
                v_xor(a4, b4), v_xor(a5, b5), v_xor(a6, b6), v_xor(a7, b7),
            );
            state[0] = v_xor(v_xor(b0, c7), $second_rotate(c0));
            state[1] = v_xor(v_xor(v_xor(b1, c0), c7), $second_rotate(c1));
            state[2] = v_xor(v_xor(b2, c1), $second_rotate(c2));
            state[3] = v_xor(v_xor(v_xor(b3, c2), c7), $second_rotate(c3));
            state[4] = v_xor(v_xor(v_xor(b4, c3), c7), $second_rotate(c4));
            state[5] = v_xor(v_xor(b5, c4), $second_rotate(c5));
            state[6] = v_xor(v_xor(b6, c5), $second_rotate(c6));
            state[7] = v_xor(v_xor(b7, c6), $second_rotate(c7));
        }
    };
}

define_v_mix_columns!(v_mix_columns_0, v_rotate_rows_1, v_rotate_rows_2);
define_v_mix_columns!(v_mix_columns_1, v_rotate_rows_and_columns_1_1, v_rotate_rows_and_columns_2_2);
define_v_mix_columns!(v_mix_columns_2, v_rotate_rows_and_columns_1_2, v_rotate_rows_2);
define_v_mix_columns!(v_mix_columns_3, v_rotate_rows_and_columns_1_3, v_rotate_rows_and_columns_2_2);

// ============================================================================
// bitslice_8 / inv_bitslice_8
// ============================================================================

/// Bitslice 8 blocks into SIMD fixsliced state.
/// Packs 4 pairs of blocks into v128 lanes.
fn bitslice_8(blocks: &[Block; 8]) -> SimdState {
    // Load u32 values from each pair
    let mut t = [[0u32; 8]; 4];
    for p in 0..4 {
        let b0 = &blocks[2 * p];
        let b1 = &blocks[2 * p + 1];
        t[p][0] = u32::from_le_bytes(b0[0x00..0x04].try_into().unwrap());
        t[p][2] = u32::from_le_bytes(b0[0x04..0x08].try_into().unwrap());
        t[p][4] = u32::from_le_bytes(b0[0x08..0x0c].try_into().unwrap());
        t[p][6] = u32::from_le_bytes(b0[0x0c..0x10].try_into().unwrap());
        t[p][1] = u32::from_le_bytes(b1[0x00..0x04].try_into().unwrap());
        t[p][3] = u32::from_le_bytes(b1[0x04..0x08].try_into().unwrap());
        t[p][5] = u32::from_le_bytes(b1[0x08..0x0c].try_into().unwrap());
        t[p][7] = u32::from_le_bytes(b1[0x0c..0x10].try_into().unwrap());
    }

    // Pack into v128: one lane per pair
    let mut state: SimdState = [v_splat(0); 8];
    for i in 0..8 {
        state[i] = v_new(t[0][i], t[1][i], t[2][i], t[3][i]);
    }

    // Apply delta_swap_2 sequence (same as scalar bitslice, on v128)
    let m0 = v_splat(0x55555555);
    v_delta_swap_2_arr(&mut state, 1, 0, 1, m0);
    v_delta_swap_2_arr(&mut state, 3, 2, 1, m0);
    v_delta_swap_2_arr(&mut state, 5, 4, 1, m0);
    v_delta_swap_2_arr(&mut state, 7, 6, 1, m0);

    let m1 = v_splat(0x33333333);
    v_delta_swap_2_arr(&mut state, 2, 0, 2, m1);
    v_delta_swap_2_arr(&mut state, 3, 1, 2, m1);
    v_delta_swap_2_arr(&mut state, 6, 4, 2, m1);
    v_delta_swap_2_arr(&mut state, 7, 5, 2, m1);

    let m2 = v_splat(0x0f0f0f0f);
    v_delta_swap_2_arr(&mut state, 4, 0, 4, m2);
    v_delta_swap_2_arr(&mut state, 5, 1, 4, m2);
    v_delta_swap_2_arr(&mut state, 6, 2, 4, m2);
    v_delta_swap_2_arr(&mut state, 7, 3, 4, m2);

    state
}

/// Inverse bitslice: extract 8 blocks from SIMD fixsliced state.
fn inv_bitslice_8(input: &SimdState) -> [Block; 8] {
    let mut t = *input;

    // Reverse delta_swap_2 sequence
    let m0 = v_splat(0x55555555);
    v_delta_swap_2_arr(&mut t, 1, 0, 1, m0);
    v_delta_swap_2_arr(&mut t, 3, 2, 1, m0);
    v_delta_swap_2_arr(&mut t, 5, 4, 1, m0);
    v_delta_swap_2_arr(&mut t, 7, 6, 1, m0);

    let m1 = v_splat(0x33333333);
    v_delta_swap_2_arr(&mut t, 2, 0, 2, m1);
    v_delta_swap_2_arr(&mut t, 3, 1, 2, m1);
    v_delta_swap_2_arr(&mut t, 6, 4, 2, m1);
    v_delta_swap_2_arr(&mut t, 7, 5, 2, m1);

    let m2 = v_splat(0x0f0f0f0f);
    v_delta_swap_2_arr(&mut t, 4, 0, 4, m2);
    v_delta_swap_2_arr(&mut t, 5, 1, 4, m2);
    v_delta_swap_2_arr(&mut t, 6, 2, 4, m2);
    v_delta_swap_2_arr(&mut t, 7, 3, 4, m2);

    // Extract lanes and write to blocks
    let mut output = [Block::default(); 8];
    for p in 0..4usize {
        let v0 = v_extract_lane(t[0], p);
        let v1 = v_extract_lane(t[1], p);
        let v2 = v_extract_lane(t[2], p);
        let v3 = v_extract_lane(t[3], p);
        let v4 = v_extract_lane(t[4], p);
        let v5 = v_extract_lane(t[5], p);
        let v6 = v_extract_lane(t[6], p);
        let v7 = v_extract_lane(t[7], p);

        // block 2*p: even-indexed t values (columns of block 0 of this pair)
        output[2 * p][0x00..0x04].copy_from_slice(&v0.to_le_bytes());
        output[2 * p][0x04..0x08].copy_from_slice(&v2.to_le_bytes());
        output[2 * p][0x08..0x0c].copy_from_slice(&v4.to_le_bytes());
        output[2 * p][0x0c..0x10].copy_from_slice(&v6.to_le_bytes());
        // block 2*p+1: odd-indexed t values (columns of block 1 of this pair)
        output[2 * p + 1][0x00..0x04].copy_from_slice(&v1.to_le_bytes());
        output[2 * p + 1][0x04..0x08].copy_from_slice(&v3.to_le_bytes());
        output[2 * p + 1][0x08..0x0c].copy_from_slice(&v5.to_le_bytes());
        output[2 * p + 1][0x0c..0x10].copy_from_slice(&v7.to_le_bytes());
    }

    output
}

// ============================================================================
// aes128_encrypt_8
// ============================================================================

/// Encrypt 8 blocks in parallel using AES-128 in fixsliced representation.
/// Non-compact (fully-unrolled) path for maximum throughput.
fn aes128_encrypt_8(rkeys: &SimdRoundKeys, state: &mut SimdState) {
    v_add_round_key(state, &rkeys[..8]);

    let mut rk_off = 8;
    loop {
        v_sub_bytes(state);
        v_mix_columns_1(state);
        v_add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        if rk_off == 80 {
            break;
        }

        v_sub_bytes(state);
        v_mix_columns_2(state);
        v_add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        v_sub_bytes(state);
        v_mix_columns_3(state);
        v_add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        v_sub_bytes(state);
        v_mix_columns_0(state);
        v_add_round_key(state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;
    }

    v_shift_rows_2(state);
    v_sub_bytes(state);
    v_add_round_key(state, &rkeys[80..]);
}

// ============================================================================
// Public API
// ============================================================================

pub struct SimdAes128 {
    simd_rkeys: SimdRoundKeys,
}

impl SimdAes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let scalar_rkeys = aes128_key_schedule(key);
        let simd_rkeys = splat_round_keys(&scalar_rkeys);
        Self { simd_rkeys }
    }

    /// Encrypt a single block in-place.
    /// Pads to 8 blocks, encrypts, keeps only the first result.
    pub fn encrypt_block(&self, block: &mut Block) {
        let mut blocks = [Block::default(); 8];
        blocks[0] = *block;
        let mut state = bitslice_8(&blocks);
        aes128_encrypt_8(&self.simd_rkeys, &mut state);
        let out = inv_bitslice_8(&state);
        *block = out[0];
    }

    /// Encrypt multiple blocks in-place, processing in chunks of 8.
    pub fn encrypt_blocks(&self, blocks: &mut [Block]) {
        let mut i = 0;
        while i + 8 <= blocks.len() {
            let chunk: &[Block; 8] = blocks[i..i + 8].try_into().unwrap();
            let mut state = bitslice_8(chunk);
            aes128_encrypt_8(&self.simd_rkeys, &mut state);
            let out = inv_bitslice_8(&state);
            blocks[i..i + 8].copy_from_slice(&out);
            i += 8;
        }
        // Handle remainder (1-7 blocks)
        if i < blocks.len() {
            let mut padded = [Block::default(); 8];
            let rem = blocks.len() - i;
            padded[..rem].copy_from_slice(&blocks[i..]);
            let mut state = bitslice_8(&padded);
            aes128_encrypt_8(&self.simd_rkeys, &mut state);
            let out = inv_bitslice_8(&state);
            blocks[i..].copy_from_slice(&out[..rem]);
        }
    }
}

// ============================================================================
// Tests (cross-validate against aes crate)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    use wasm_bindgen_test::*;

    /// NIST AES-128 test vector: all-zero key, all-zero plaintext.
    #[wasm_bindgen_test]
    fn test_nist_zero_vector() {
        let key = [0u8; 16];
        let simd = SimdAes128::new(&key);
        let reference = Aes128::new(&key.into());

        let mut block_simd = Block::default();
        let mut block_ref = Block::default();
        simd.encrypt_block(&mut block_simd);
        reference.encrypt_block(&mut block_ref);

        assert_eq!(block_simd, block_ref, "NIST zero vector mismatch");
    }

    /// Test with non-trivial key and multiple single-block encryptions.
    #[wasm_bindgen_test]
    fn test_various_keys() {
        for key_byte in [0x00, 0x01, 0x42, 0x7f, 0xff] {
            let key = [key_byte; 16];
            let simd = SimdAes128::new(&key);
            let reference = Aes128::new(&key.into());

            for pt_byte in [0x00, 0x01, 0x80, 0xff] {
                let mut block_simd = Block::default();
                let mut block_ref = Block::default();
                block_simd.iter_mut().for_each(|b| *b = pt_byte);
                block_ref.iter_mut().for_each(|b| *b = pt_byte);

                simd.encrypt_block(&mut block_simd);
                reference.encrypt_block(&mut block_ref);

                assert_eq!(block_simd, block_ref,
                    "Mismatch key=0x{key_byte:02x} pt=0x{pt_byte:02x}");
            }
        }
    }

    /// Test encrypt_blocks with various chunk sizes (1, 2, 7, 8, 9, 15, 16, 17).
    #[wasm_bindgen_test]
    fn test_encrypt_blocks_sizes() {
        let key = [0x5a; 16];
        let simd = SimdAes128::new(&key);
        let reference = Aes128::new(&key.into());

        for count in [1, 2, 7, 8, 9, 15, 16, 17] {
            let mut blocks_simd: Vec<Block> = (0..count)
                .map(|i| {
                    let mut b = Block::default();
                    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    b
                })
                .collect();
            let mut blocks_ref = blocks_simd.clone();

            simd.encrypt_blocks(&mut blocks_simd);
            reference.encrypt_blocks(&mut blocks_ref);

            for j in 0..count {
                assert_eq!(blocks_simd[j], blocks_ref[j],
                    "Mismatch at block {j}/{count}");
            }
        }
    }

    /// Counter-mode test: encrypts sequential counter blocks (as used in bitstring.rs).
    #[wasm_bindgen_test]
    fn test_counter_mode_equivalence() {
        let key = [0xab; 16];
        let simd = SimdAes128::new(&key);
        let reference = Aes128::new(&key.into());

        let mut blocks_simd = [Block::default(); 8];
        let mut blocks_ref = [Block::default(); 8];
        for i in 0..8u64 {
            blocks_simd[i as usize][..8].copy_from_slice(&i.to_le_bytes());
            blocks_ref[i as usize][..8].copy_from_slice(&i.to_le_bytes());
        }

        simd.encrypt_blocks(&mut blocks_simd);
        reference.encrypt_blocks(&mut blocks_ref);

        for i in 0..8 {
            assert_eq!(blocks_simd[i], blocks_ref[i],
                "Counter mode mismatch at block {i}");
        }
    }
}
