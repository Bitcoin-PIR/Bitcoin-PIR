//! Platform-abstracted SIMD wrappers.
//!
//! Provides a V128 type alias and uniform function API that compiles
//! on both aarch64 (NEON + AES crypto) and x86_64 (SSE + AES-NI).
//! Also provides V512 wide operations for x86_64 AVX-512 VAES batching.

// ================================================================
// Platform type aliases
// ================================================================

#[cfg(target_arch = "aarch64")]
pub use std::arch::aarch64::uint8x16_t as V128;

#[cfg(target_arch = "x86_64")]
pub use std::arch::x86_64::__m128i as V128;

#[cfg(target_arch = "wasm32")]
pub use core::arch::wasm32::v128 as V128;

// ================================================================
// aarch64 NEON + AES crypto implementations
// ================================================================

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::V128;
    use std::arch::aarch64::*;

    #[inline(always)]
    pub unsafe fn zero() -> V128 { vdupq_n_u8(0) }

    #[inline(always)]
    pub unsafe fn c_ff() -> V128 { vdupq_n_u8(0xFF) }

    #[inline(always)]
    pub unsafe fn xor2(a: V128, b: V128) -> V128 { veorq_u8(a, b) }

    #[inline(always)]
    pub unsafe fn xor3(a: V128, b: V128, c: V128) -> V128 { veor3q_u8(a, b, c) }

    #[inline(always)]
    pub unsafe fn and128(a: V128, b: V128) -> V128 { vandq_u8(a, b) }

    #[inline(always)]
    pub unsafe fn or128(a: V128, b: V128) -> V128 { vorrq_u8(a, b) }

    #[inline(always)]
    pub unsafe fn andnot(a: V128, b: V128) -> V128 { vbicq_u8(b, a) }

    #[inline(always)]
    pub unsafe fn shuffle(x: V128, sh: V128) -> V128 { vqtbl1q_u8(x, sh) }

    #[inline(always)]
    pub unsafe fn aesenc(state: V128, rk: V128) -> V128 {
        veorq_u8(vaesmcq_u8(vaeseq_u8(state, zero())), rk)
    }

    #[inline(always)]
    pub unsafe fn aesdec(state: V128, rk: V128) -> V128 {
        veorq_u8(vaesimcq_u8(vaesdq_u8(state, zero())), rk)
    }

    #[inline(always)]
    pub unsafe fn aesenclast(state: V128, rk: V128) -> V128 {
        veorq_u8(vaeseq_u8(state, zero()), rk)
    }

    #[inline(always)]
    pub unsafe fn aesdeclast(state: V128, rk: V128) -> V128 {
        veorq_u8(vaesdq_u8(state, zero()), rk)
    }

    #[inline(always)]
    pub unsafe fn aesimc(state: V128) -> V128 { vaesimcq_u8(state) }

    #[inline(always)]
    pub unsafe fn load128(ptr: *const u8) -> V128 { vld1q_u8(ptr) }

    #[inline(always)]
    pub unsafe fn store128(ptr: *mut u8, x: V128) { vst1q_u8(ptr, x) }

    #[inline(always)]
    pub unsafe fn combine(s1: V128, s2: V128) -> V128 {
        vorrq_u8(vqtbl1q_u8(s1, s2), vceqq_u8(s2, c_ff()))
    }

    #[inline(always)]
    pub unsafe fn blend(a: V128, b: V128, mask: V128) -> V128 { vbslq_u8(mask, b, a) }

    #[inline(always)]
    pub unsafe fn cmpeq8(a: V128, b: V128) -> V128 { vceqq_u8(a, b) }

    #[inline(always)]
    pub unsafe fn add8(a: V128, b: V128) -> V128 { vaddq_u8(a, b) }

    #[inline(always)]
    pub unsafe fn from_bytes(bytes: &[u8; 16]) -> V128 { vld1q_u8(bytes.as_ptr()) }

    #[inline(always)]
    pub unsafe fn splat8(v: u8) -> V128 { vdupq_n_u8(v) }

    #[inline(always)]
    pub unsafe fn extract_lo64(x: V128) -> u64 {
        vgetq_lane_u64::<0>(vreinterpretq_u64_u8(x))
    }

    #[inline(always)]
    pub unsafe fn extract_hi64(x: V128) -> u64 {
        vgetq_lane_u64::<1>(vreinterpretq_u64_u8(x))
    }

    #[inline(always)]
    pub unsafe fn extract_byte<const LANE: i32>(x: V128) -> u8 {
        vgetq_lane_u8::<LANE>(x)
    }

    #[inline(always)]
    pub unsafe fn from_u64x2(lo: u64, hi: u64) -> V128 {
        vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi)))
    }

    #[inline(always)]
    pub unsafe fn from_u32_low(v: u32) -> V128 {
        let arr: [u32; 4] = [v, 0, 0, 0];
        vreinterpretq_u8_u32(vld1q_u32(arr.as_ptr()))
    }

    #[inline(always)]
    pub unsafe fn bslli_3(x: V128) -> V128 { vextq_u8::<13>(zero(), x) }

    #[inline(always)]
    pub unsafe fn slli_epi64_32(x: V128) -> V128 {
        vreinterpretq_u8_u64(vshlq_n_u64::<32>(vreinterpretq_u64_u8(x)))
    }

    #[inline(always)]
    pub unsafe fn clmul_lo(a: V128, b: u64) -> V128 {
        let a_lo = vgetq_lane_u64::<0>(vreinterpretq_u64_u8(a));
        std::mem::transmute(vmull_p64(a_lo, b))
    }
}

// ================================================================
// x86_64 SSE + AES-NI implementations
// ================================================================

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::V128;
    use std::arch::x86_64::*;

    #[inline(always)]
    pub unsafe fn zero() -> V128 { _mm_setzero_si128() }

    #[inline(always)]
    pub unsafe fn c_ff() -> V128 { _mm_set1_epi8(-1) }

    #[inline(always)]
    pub unsafe fn xor2(a: V128, b: V128) -> V128 { _mm_xor_si128(a, b) }

    #[inline(always)]
    pub unsafe fn xor3(a: V128, b: V128, c: V128) -> V128 {
        _mm_xor_si128(_mm_xor_si128(a, b), c)
    }

    #[inline(always)]
    pub unsafe fn and128(a: V128, b: V128) -> V128 { _mm_and_si128(a, b) }

    #[inline(always)]
    pub unsafe fn or128(a: V128, b: V128) -> V128 { _mm_or_si128(a, b) }

    /// (~a) & b  — matches x86 _mm_andnot_si128(a, b)
    #[inline(always)]
    pub unsafe fn andnot(a: V128, b: V128) -> V128 { _mm_andnot_si128(a, b) }

    #[inline(always)]
    pub unsafe fn shuffle(x: V128, sh: V128) -> V128 { _mm_shuffle_epi8(x, sh) }

    #[inline(always)]
    pub unsafe fn aesenc(state: V128, rk: V128) -> V128 { _mm_aesenc_si128(state, rk) }

    #[inline(always)]
    pub unsafe fn aesdec(state: V128, rk: V128) -> V128 { _mm_aesdec_si128(state, rk) }

    #[inline(always)]
    pub unsafe fn aesenclast(state: V128, rk: V128) -> V128 { _mm_aesenclast_si128(state, rk) }

    #[inline(always)]
    pub unsafe fn aesdeclast(state: V128, rk: V128) -> V128 { _mm_aesdeclast_si128(state, rk) }

    #[inline(always)]
    pub unsafe fn aesimc(state: V128) -> V128 { _mm_aesimc_si128(state) }

    #[inline(always)]
    pub unsafe fn load128(ptr: *const u8) -> V128 { _mm_loadu_si128(ptr as *const V128) }

    #[inline(always)]
    pub unsafe fn store128(ptr: *mut u8, x: V128) { _mm_storeu_si128(ptr as *mut V128, x) }

    #[inline(always)]
    pub unsafe fn combine(s1: V128, s2: V128) -> V128 {
        _mm_or_si128(_mm_shuffle_epi8(s1, s2), _mm_cmpeq_epi8(s2, c_ff()))
    }

    #[inline(always)]
    pub unsafe fn blend(a: V128, b: V128, mask: V128) -> V128 { _mm_blendv_epi8(a, b, mask) }

    #[inline(always)]
    pub unsafe fn cmpeq8(a: V128, b: V128) -> V128 { _mm_cmpeq_epi8(a, b) }

    #[inline(always)]
    pub unsafe fn add8(a: V128, b: V128) -> V128 { _mm_add_epi8(a, b) }

    #[inline(always)]
    pub unsafe fn from_bytes(bytes: &[u8; 16]) -> V128 {
        _mm_loadu_si128(bytes.as_ptr() as *const V128)
    }

    #[inline(always)]
    pub unsafe fn splat8(v: u8) -> V128 { _mm_set1_epi8(v as i8) }

    #[inline(always)]
    pub unsafe fn extract_lo64(x: V128) -> u64 { _mm_cvtsi128_si64(x) as u64 }

    #[inline(always)]
    pub unsafe fn extract_hi64(x: V128) -> u64 { _mm_extract_epi64::<1>(x) as u64 }

    #[inline(always)]
    pub unsafe fn extract_byte<const LANE: i32>(x: V128) -> u8 {
        _mm_extract_epi8::<LANE>(x) as u8
    }

    #[inline(always)]
    pub unsafe fn from_u64x2(lo: u64, hi: u64) -> V128 {
        _mm_set_epi64x(hi as i64, lo as i64)
    }

    #[inline(always)]
    pub unsafe fn from_u32_low(v: u32) -> V128 { _mm_cvtsi32_si128(v as i32) }

    #[inline(always)]
    pub unsafe fn bslli_3(x: V128) -> V128 { _mm_bslli_si128::<3>(x) }

    #[inline(always)]
    pub unsafe fn slli_epi64_32(x: V128) -> V128 { _mm_slli_epi64::<32>(x) }

    #[inline(always)]
    pub unsafe fn clmul_lo(a: V128, b: u64) -> V128 {
        _mm_clmulepi64_si128(a, _mm_set_epi64x(0, b as i64), 0x00)
    }
}

// ================================================================
// wasm32 SIMD implementations (v128 + software AES via swizzle)
// ================================================================

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::V128;
    use core::arch::wasm32::*;

    // AES forward S-box split into 16 chunks of 16 bytes each.
    // Chunk i contains SBOX[i*16 .. i*16+16].
    // SubBytes uses i8x16_swizzle per chunk with low-nibble indices,
    // selected by high-nibble equality — constant-time, no data-dependent
    // memory access.
    static SBOX_CHUNKS: [[u8; 16]; 16] = [
        [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
        [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0],
        [0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15],
        [0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75],
        [0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84],
        [0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf],
        [0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8],
        [0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2],
        [0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73],
        [0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb],
        [0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79],
        [0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08],
        [0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a],
        [0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e],
        [0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf],
        [0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16],
    ];

    // AES inverse S-box split into 16 chunks of 16 bytes.
    static INV_SBOX_CHUNKS: [[u8; 16]; 16] = [
        [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb],
        [0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb],
        [0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e],
        [0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25],
        [0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92],
        [0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84],
        [0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06],
        [0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b],
        [0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73],
        [0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e],
        [0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b],
        [0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4],
        [0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f],
        [0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef],
        [0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61],
        [0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d],
    ];

    // ----------------------------------------------------------------
    // Internal helpers: constant-time AES sub-operations via SIMD
    // ----------------------------------------------------------------

    /// Load a 16-byte chunk into v128
    #[inline(always)]
    unsafe fn load_chunk(chunk: &[u8; 16]) -> v128 {
        v128_load(chunk.as_ptr() as *const v128)
    }

    /// SubBytes via 16-chunk swizzle lookup (constant-time).
    /// For each input byte, high nibble selects the S-box chunk,
    /// low nibble indexes within it via i8x16_swizzle.
    #[inline(always)]
    unsafe fn sub_bytes_simd(state: v128) -> v128 {
        let lo_nib = v128_and(state, u8x16_splat(0x0F));
        let hi_nib = u8x16_shr(state, 4);
        let mut result = u8x16_splat(0);
        macro_rules! chunk_lookup {
            ($i:literal) => {{
                let chunk = load_chunk(&SBOX_CHUNKS[$i]);
                let looked = i8x16_swizzle(chunk, lo_nib);
                let mask = i8x16_eq(hi_nib, u8x16_splat($i));
                result = v128_or(result, v128_and(looked, mask));
            }};
        }
        chunk_lookup!(0);  chunk_lookup!(1);  chunk_lookup!(2);  chunk_lookup!(3);
        chunk_lookup!(4);  chunk_lookup!(5);  chunk_lookup!(6);  chunk_lookup!(7);
        chunk_lookup!(8);  chunk_lookup!(9);  chunk_lookup!(10); chunk_lookup!(11);
        chunk_lookup!(12); chunk_lookup!(13); chunk_lookup!(14); chunk_lookup!(15);
        result
    }

    /// Inverse SubBytes via 16-chunk swizzle lookup (constant-time).
    #[inline(always)]
    unsafe fn inv_sub_bytes_simd(state: v128) -> v128 {
        let lo_nib = v128_and(state, u8x16_splat(0x0F));
        let hi_nib = u8x16_shr(state, 4);
        let mut result = u8x16_splat(0);
        macro_rules! chunk_lookup {
            ($i:literal) => {{
                let chunk = load_chunk(&INV_SBOX_CHUNKS[$i]);
                let looked = i8x16_swizzle(chunk, lo_nib);
                let mask = i8x16_eq(hi_nib, u8x16_splat($i));
                result = v128_or(result, v128_and(looked, mask));
            }};
        }
        chunk_lookup!(0);  chunk_lookup!(1);  chunk_lookup!(2);  chunk_lookup!(3);
        chunk_lookup!(4);  chunk_lookup!(5);  chunk_lookup!(6);  chunk_lookup!(7);
        chunk_lookup!(8);  chunk_lookup!(9);  chunk_lookup!(10); chunk_lookup!(11);
        chunk_lookup!(12); chunk_lookup!(13); chunk_lookup!(14); chunk_lookup!(15);
        result
    }

    /// ShiftRows (column-major): [0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11]
    #[inline(always)]
    unsafe fn shift_rows_simd(s: v128) -> v128 {
        i8x16_shuffle::<0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11>(s, s)
    }

    /// InvShiftRows (column-major): [0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3]
    #[inline(always)]
    unsafe fn inv_shift_rows_simd(s: v128) -> v128 {
        i8x16_shuffle::<0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3>(s, s)
    }

    /// GF(2^8) xtime on each byte in parallel: (x<<1) ^ (0x1b if high bit set)
    #[inline(always)]
    unsafe fn xtime_simd(x: v128) -> v128 {
        let shifted = u8x16_shl(x, 1);
        let high_mask = i8x16_shr(x, 7);  // 0x00 or 0xFF (arithmetic shift)
        let reduction = v128_and(high_mask, u8x16_splat(0x1b));
        v128_xor(shifted, reduction)
    }

    /// Forward MixColumns via SIMD rotations + xtime.
    /// For column [a,b,c,d]: out[i] = state[i] ^ (a^b^c^d) ^ xtime(state[i] ^ rot1[i])
    #[inline(always)]
    unsafe fn mix_columns_simd(s: v128) -> v128 {
        // Rotate each 4-byte column by 1 position
        let rot1 = i8x16_shuffle::<1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12>(s, s);
        // Pairwise XOR: [a^b, b^c, c^d, d^a] per column
        let xor_pairs = v128_xor(s, rot1);
        // Column-wide XOR: a^b^c^d in every position
        let rot2_pairs = i8x16_shuffle::<2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13>(xor_pairs, xor_pairs);
        let t = v128_xor(xor_pairs, rot2_pairs);
        // result = state ^ t ^ xtime(xor_pairs)
        v128_xor(v128_xor(s, t), xtime_simd(xor_pairs))
    }

    /// Inverse MixColumns via SIMD.
    /// Computes x2=2*s, x4=4*s, x8=8*s, then combines:
    ///   14*s = x8^x4^x2, 11*s = x8^x2^s, 13*s = x8^x4^s, 9*s = x8^s
    /// with column rotations to place the right multiplier per row.
    #[inline(always)]
    unsafe fn inv_mix_columns_simd(s: v128) -> v128 {
        let x2 = xtime_simd(s);
        let x4 = xtime_simd(x2);
        let x8 = xtime_simd(x4);
        // Multiples of each byte
        let x14 = v128_xor(v128_xor(x8, x4), x2);  // 8+4+2
        let x11 = v128_xor(v128_xor(x8, x2), s);    // 8+2+1
        let x13 = v128_xor(v128_xor(x8, x4), s);    // 8+4+1
        let x9  = v128_xor(x8, s);                   // 8+1
        // Rotate within columns and combine:
        // row0: 14*a + 11*b + 13*c + 9*d
        // row1: 9*a + 14*b + 11*c + 13*d  etc.
        let rot1_x11 = i8x16_shuffle::<1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12>(x11, x11);
        let rot2_x13 = i8x16_shuffle::<2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13>(x13, x13);
        let rot3_x9  = i8x16_shuffle::<3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14>(x9, x9);
        v128_xor(v128_xor(x14, rot1_x11), v128_xor(rot2_x13, rot3_x9))
    }

    // ----------------------------------------------------------------
    // Public API (matches aarch64/x86_64 signatures)
    // ----------------------------------------------------------------

    #[inline(always)]
    pub unsafe fn zero() -> V128 { u8x16_splat(0) }

    #[inline(always)]
    pub unsafe fn c_ff() -> V128 { u8x16_splat(0xFF) }

    #[inline(always)]
    pub unsafe fn xor2(a: V128, b: V128) -> V128 { v128_xor(a, b) }

    #[inline(always)]
    pub unsafe fn xor3(a: V128, b: V128, c: V128) -> V128 { v128_xor(v128_xor(a, b), c) }

    #[inline(always)]
    pub unsafe fn and128(a: V128, b: V128) -> V128 { v128_and(a, b) }

    #[inline(always)]
    pub unsafe fn or128(a: V128, b: V128) -> V128 { v128_or(a, b) }

    /// (~a) & b
    #[inline(always)]
    pub unsafe fn andnot(a: V128, b: V128) -> V128 { v128_andnot(b, a) }

    /// Byte shuffle: if index byte has high bit set → 0, else → x[idx & 0x0F]
    #[inline(always)]
    pub unsafe fn shuffle(x: V128, sh: V128) -> V128 { i8x16_swizzle(x, sh) }

    /// AES single round: SubBytes → ShiftRows → MixColumns → XOR rk
    #[inline(always)]
    pub unsafe fn aesenc(state: V128, rk: V128) -> V128 {
        let s = sub_bytes_simd(state);
        let s = shift_rows_simd(s);
        let s = mix_columns_simd(s);
        v128_xor(s, rk)
    }

    /// AES inverse round: InvSubBytes → InvShiftRows → InvMixColumns → XOR rk
    #[inline(always)]
    pub unsafe fn aesdec(state: V128, rk: V128) -> V128 {
        let s = inv_sub_bytes_simd(state);
        let s = inv_shift_rows_simd(s);
        let s = inv_mix_columns_simd(s);
        v128_xor(s, rk)
    }

    /// AES last round (no MixColumns): SubBytes → ShiftRows → XOR rk
    #[inline(always)]
    pub unsafe fn aesenclast(state: V128, rk: V128) -> V128 {
        let s = sub_bytes_simd(state);
        let s = shift_rows_simd(s);
        v128_xor(s, rk)
    }

    /// AES inverse last round (no InvMixColumns): InvSubBytes → InvShiftRows → XOR rk
    #[inline(always)]
    pub unsafe fn aesdeclast(state: V128, rk: V128) -> V128 {
        let s = inv_sub_bytes_simd(state);
        let s = inv_shift_rows_simd(s);
        v128_xor(s, rk)
    }

    /// InvMixColumns only
    #[inline(always)]
    pub unsafe fn aesimc(state: V128) -> V128 { inv_mix_columns_simd(state) }

    #[inline(always)]
    pub unsafe fn load128(ptr: *const u8) -> V128 { v128_load(ptr as *const v128) }

    #[inline(always)]
    pub unsafe fn store128(ptr: *mut u8, x: V128) { v128_store(ptr as *mut v128, x) }

    /// shuffle(s1, s2) | cmpeq(s2, 0xFF)
    #[inline(always)]
    pub unsafe fn combine(s1: V128, s2: V128) -> V128 {
        v128_or(i8x16_swizzle(s1, s2), i8x16_eq(s2, u8x16_splat(0xFF)))
    }

    /// Per-bit blend: result = (mask & b) | (~mask & a)
    #[inline(always)]
    pub unsafe fn blend(a: V128, b: V128, mask: V128) -> V128 {
        v128_bitselect(b, a, mask)
    }

    #[inline(always)]
    pub unsafe fn cmpeq8(a: V128, b: V128) -> V128 { i8x16_eq(a, b) }

    #[inline(always)]
    pub unsafe fn add8(a: V128, b: V128) -> V128 { u8x16_add(a, b) }

    #[inline(always)]
    pub unsafe fn from_bytes(bytes: &[u8; 16]) -> V128 {
        v128_load(bytes.as_ptr() as *const v128)
    }

    #[inline(always)]
    pub unsafe fn splat8(v: u8) -> V128 { u8x16_splat(v) }

    #[inline(always)]
    pub unsafe fn extract_lo64(x: V128) -> u64 {
        u64x2_extract_lane::<0>(x) as u64
    }

    #[inline(always)]
    pub unsafe fn extract_hi64(x: V128) -> u64 {
        u64x2_extract_lane::<1>(x) as u64
    }

    #[inline(always)]
    pub unsafe fn extract_byte<const LANE: i32>(x: V128) -> u8 {
        *(&x as *const V128 as *const u8).add(LANE as usize)
    }

    #[inline(always)]
    pub unsafe fn from_u64x2(lo: u64, hi: u64) -> V128 {
        u64x2_replace_lane::<1>(u64x2_replace_lane::<0>(u64x2_splat(0), lo), hi)
    }

    #[inline(always)]
    pub unsafe fn from_u32_low(v: u32) -> V128 {
        u32x4_replace_lane::<0>(u32x4_splat(0), v)
    }

    /// Byte-shift left by 3: [0,0,0, x[0], x[1], ..., x[12]]
    #[inline(always)]
    pub unsafe fn bslli_3(x: V128) -> V128 {
        let z = u8x16_splat(0);
        i8x16_shuffle::<0,1,2, 16,17,18,19,20,21,22,23,24,25,26,27,28>(z, x)
    }

    /// Shift each 64-bit lane left by 32 bits
    #[inline(always)]
    pub unsafe fn slli_epi64_32(x: V128) -> V128 { u64x2_shl(x, 32) }

    /// Carry-less multiply: low 64 bits of a × b → 128-bit result (scalar, no WASM clmul)
    #[inline(always)]
    pub unsafe fn clmul_lo(a: V128, b: u64) -> V128 {
        let a_lo = extract_lo64(a);
        let mut r_lo: u64 = 0;
        let mut r_hi: u64 = 0;
        let mut shifted_lo = a_lo;
        let mut shifted_hi: u64 = 0;
        for i in 0..64 {
            if (b >> i) & 1 != 0 {
                r_lo ^= shifted_lo;
                r_hi ^= shifted_hi;
            }
            shifted_hi = (shifted_hi << 1) | (shifted_lo >> 63);
            shifted_lo <<= 1;
        }
        from_u64x2(r_lo, r_hi)
    }
}

// Re-export all functions from the platform-specific module
pub use imp::*;

// ================================================================
// x86_64 AVX-512 VAES wide operations (4 × 128-bit lanes)
// ================================================================

#[cfg(target_arch = "x86_64")]
pub mod wide {
    use std::arch::x86_64::*;
    use super::V128;

    pub type V512 = __m512i;

    #[inline(always)]
    pub unsafe fn zero_x4() -> V512 { _mm512_setzero_si512() }

    #[inline(always)]
    pub unsafe fn broadcast(x: V128) -> V512 { _mm512_broadcast_i32x4(x) }

    /// Load 4 independent 128-bit blocks into a 512-bit register.
    #[inline(always)]
    pub unsafe fn load_4x128(b0: *const u8, b1: *const u8, b2: *const u8, b3: *const u8) -> V512 {
        let v0 = _mm_loadu_si128(b0 as *const __m128i);
        let v1 = _mm_loadu_si128(b1 as *const __m128i);
        let v2 = _mm_loadu_si128(b2 as *const __m128i);
        let v3 = _mm_loadu_si128(b3 as *const __m128i);
        let lo = _mm256_inserti128_si256(_mm256_castsi128_si256(v0), v1, 1);
        let hi = _mm256_inserti128_si256(_mm256_castsi128_si256(v2), v3, 1);
        _mm512_inserti64x4(_mm512_castsi256_si512(lo), hi, 1)
    }

    /// Store 4 lanes of a 512-bit register to separate buffers.
    #[inline(always)]
    pub unsafe fn store_4x128(x: V512, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        let lo = _mm512_castsi512_si256(x);
        let hi = _mm512_extracti64x4_epi64(x, 1);
        _mm_storeu_si128(b0 as *mut __m128i, _mm256_castsi256_si128(lo));
        _mm_storeu_si128(b1 as *mut __m128i, _mm256_extracti128_si256(lo, 1));
        _mm_storeu_si128(b2 as *mut __m128i, _mm256_castsi256_si128(hi));
        _mm_storeu_si128(b3 as *mut __m128i, _mm256_extracti128_si256(hi, 1));
    }

    /// Extract one 128-bit lane from a 512-bit register.
    #[inline(always)]
    pub unsafe fn extract_lane(x: V512, lane: usize) -> V128 {
        match lane {
            0 => _mm512_castsi512_si128(x),
            1 => _mm256_extracti128_si256(_mm512_castsi512_si256(x), 1),
            2 => _mm512_castsi512_si128(_mm512_shuffle_i64x2(x, x, 0b_00_00_10_10)),
            3 => _mm512_castsi512_si128(_mm512_shuffle_i64x2(x, x, 0b_00_00_11_11)),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub unsafe fn xor2_x4(a: V512, b: V512) -> V512 { _mm512_xor_si512(a, b) }

    #[inline(always)]
    pub unsafe fn xor3_x4(a: V512, b: V512, c: V512) -> V512 {
        _mm512_ternarylogic_epi64(a, b, c, 0x96)
    }

    #[inline(always)]
    pub unsafe fn and_x4(a: V512, b: V512) -> V512 { _mm512_and_si512(a, b) }

    #[inline(always)]
    pub unsafe fn shuffle_x4(x: V512, sh: V128) -> V512 {
        _mm512_shuffle_epi8(x, broadcast(sh))
    }

    #[inline(always)]
    pub unsafe fn aesenc_x4(state: V512, rk: V128) -> V512 {
        _mm512_aesenc_epi128(state, broadcast(rk))
    }

    #[inline(always)]
    pub unsafe fn aesdec_x4(state: V512, rk: V128) -> V512 {
        _mm512_aesdec_epi128(state, broadcast(rk))
    }

    #[inline(always)]
    pub unsafe fn aesenclast_x4(state: V512, rk: V128) -> V512 {
        _mm512_aesenclast_epi128(state, broadcast(rk))
    }

    #[inline(always)]
    pub unsafe fn aesdeclast_x4(state: V512, rk: V128) -> V512 {
        _mm512_aesdeclast_epi128(state, broadcast(rk))
    }

    #[inline(always)]
    pub unsafe fn clmul_lo_x4(a: V512, b: V128) -> V512 {
        _mm512_clmulepi64_epi128(a, broadcast(b), 0x00)
    }

    #[inline(always)]
    pub unsafe fn bslli_3_x4(x: V512) -> V512 { _mm512_bslli_epi128::<3>(x) }

    #[inline(always)]
    pub unsafe fn blend_x4(a: V512, b: V512, mask: V512) -> V512 {
        // Byte-wise blend using ternary logic: (mask & b) | (~mask & a) = 0xCA
        _mm512_ternarylogic_epi64(mask, b, a, 0xCA)
    }

    #[inline(always)]
    pub unsafe fn splat8_x4(v: u8) -> V512 { _mm512_set1_epi8(v as i8) }

    /// andnot_x4: (~a) & b
    #[inline(always)]
    pub unsafe fn andnot_x4(a: V512, b: V512) -> V512 { _mm512_andnot_si512(a, b) }

    #[inline(always)]
    pub unsafe fn slli_epi64_32_x4(x: V512) -> V512 { _mm512_slli_epi64(x, 32) }
}
