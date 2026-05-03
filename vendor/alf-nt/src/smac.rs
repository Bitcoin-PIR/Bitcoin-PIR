//! SMAC-3 routines (Sequential Message Authentication Code).

use crate::simd::*;

pub const SMAC_SIGMA_BYTES: [u8; 16] = [7, 14, 15, 10, 12, 13, 3, 0, 4, 6, 1, 5, 8, 11, 2, 9];
pub const SMAC_CONST_BYTES: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[inline(always)]
pub unsafe fn smac_round(s1: V128, s2: V128, s3: V128, m: V128) -> (V128, V128, V128) {
    let sigma = from_bytes(&SMAC_SIGMA_BYTES);
    let new_s1 = shuffle(xor3(s2, s3, m), sigma);
    let new_s2 = aesenc(s1, m);
    let new_s3 = aesenc(s2, m);
    (new_s1, new_s2, new_s3)
}

#[inline]
pub unsafe fn smac_initfinal(a1: V128, a2: V128, a3: V128, m: V128) -> (V128, V128, V128) {
    let (mut b1, mut b2, mut b3) = (a1, a2, a3);
    for _ in 0..9 {
        (b1, b2, b3) = smac_round(b1, b2, b3, m);
    }
    (xor2(b1, a1), xor2(b2, a2), xor2(b3, a3))
}

#[inline]
pub unsafe fn smac_initfinal1(a1: V128, a2: V128, a3: V128) -> (V128, V128, V128) {
    let sc = from_bytes(&SMAC_CONST_BYTES);
    smac_initfinal(a1, a2, a3, sc)
}

pub unsafe fn smac_compress_u16(a1: &mut V128, a2: &mut V128, a3: &mut V128, n: i64, x: *const u16) {
    let sc = from_bytes(&SMAC_CONST_BYTES);
    let mut i: i64 = 0;

    while i <= n - 24 {
        let m0 = load128(x.add(i as usize) as *const u8);
        let m1 = load128(x.add((i + 8) as usize) as *const u8);
        let m2 = load128(x.add((i + 16) as usize) as *const u8);
        (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, m0);
        (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, m1);
        (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, m2);
        (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, sc);
        i += 24;
    }

    if i == n { return; }

    while i <= n - 8 {
        let m = load128(x.add(i as usize) as *const u8);
        (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, m);
        i += 8;
    }

    if i < n {
        let mut tmp = [0u16; 8];
        let remaining = (n - i) as usize;
        std::ptr::copy_nonoverlapping(x.add(i as usize), tmp.as_mut_ptr(), remaining);
        let m = load128(tmp.as_ptr() as *const u8);
        (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, m);
    }

    (*a1, *a2, *a3) = smac_round(*a1, *a2, *a3, sc);
}
