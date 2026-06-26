//! Small constant-shape selection helpers.
//!
//! These helpers make the ORAM hot loops easier to audit. They wrap `subtle`
//! primitives instead of hand-rolling the optimizer barrier and conditional
//! assignment logic. They are still not a substitute for inspecting optimized
//! assembly on the SEV-SNP target.

use subtle::{ConditionallySelectable, ConstantTimeEq};

/// A one-bit choice value backed by `subtle`'s optimizer-barrier wrapper.
pub type Choice = subtle::Choice;

/// Normalize a bool into a one-bit choice.
#[inline]
pub fn choice_from_bool(value: bool) -> Choice {
    Choice::from(value as u8)
}

/// Return `1 - choice` for one-bit choices.
#[inline]
pub fn not(choice: Choice) -> Choice {
    !choice
}

/// Return `lhs & rhs` for one-bit choices.
#[inline]
pub fn and(lhs: Choice, rhs: Choice) -> Choice {
    lhs & rhs
}

/// Return `lhs | rhs` for one-bit choices.
#[inline]
pub fn or(lhs: Choice, rhs: Choice) -> Choice {
    lhs | rhs
}

/// Convert a choice into an all-zero or all-one byte mask.
#[inline]
pub fn mask8(choice: Choice) -> u8 {
    0u8.wrapping_sub(choice.unwrap_u8())
}

/// Convert a choice into an all-zero or all-one u32 mask.
#[inline]
pub fn mask32(choice: Choice) -> u32 {
    0u32.wrapping_sub(choice.unwrap_u8() as u32)
}

/// Convert a choice into an all-zero or all-one u64 mask.
#[inline]
pub fn mask64(choice: Choice) -> u64 {
    0u64.wrapping_sub(choice.unwrap_u8() as u64)
}

/// Constant-shape `value == 0` for u64.
#[inline]
pub fn is_zero_u64(value: u64) -> Choice {
    value.ct_eq(&0)
}

/// Constant-shape equality for u64.
#[inline]
pub fn eq_u64(lhs: u64, rhs: u64) -> Choice {
    lhs.ct_eq(&rhs)
}

/// Constant-shape equality for u32.
#[inline]
pub fn eq_u32(lhs: u32, rhs: u32) -> Choice {
    lhs.ct_eq(&rhs)
}

/// Constant-shape equality for usize.
#[inline]
pub fn eq_usize(lhs: usize, rhs: usize) -> Choice {
    lhs.ct_eq(&rhs)
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_u8(dst: &mut u8, src: u8, choice: Choice) {
    dst.conditional_assign(&src, choice);
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_u32(dst: &mut u32, src: u32, choice: Choice) {
    dst.conditional_assign(&src, choice);
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_u64(dst: &mut u64, src: u64, choice: Choice) {
    dst.conditional_assign(&src, choice);
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_usize(dst: &mut usize, src: usize, choice: Choice) {
    let mask = 0usize.wrapping_sub(choice.unwrap_u8() as usize);
    *dst ^= (*dst ^ src) & mask;
}

/// Conditionally copy `src` into `dst`.
#[inline]
pub fn cmov_bytes(dst: &mut [u8], src: &[u8], choice: Choice) {
    debug_assert_eq!(dst.len(), src.len());
    for (dst, src) in dst.iter_mut().zip(src.iter()) {
        dst.conditional_assign(src, choice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_helpers_work() {
        assert_eq!(eq_u64(7, 7).unwrap_u8(), 1);
        assert_eq!(eq_u64(7, 8).unwrap_u8(), 0);
        assert_eq!(eq_u32(9, 9).unwrap_u8(), 1);
        assert_eq!(eq_u32(9, 10).unwrap_u8(), 0);
        assert_eq!(eq_usize(11, 11).unwrap_u8(), 1);
        assert_eq!(eq_usize(11, 12).unwrap_u8(), 0);
    }

    #[test]
    fn cmov_helpers_select() {
        let mut word = 1u64;
        cmov_u64(&mut word, 7, choice_from_bool(false));
        assert_eq!(word, 1);
        cmov_u64(&mut word, 7, choice_from_bool(true));
        assert_eq!(word, 7);

        let mut idx = 3usize;
        cmov_usize(&mut idx, 9, choice_from_bool(false));
        assert_eq!(idx, 3);
        cmov_usize(&mut idx, 9, choice_from_bool(true));
        assert_eq!(idx, 9);

        let mut bytes = *b"abcd";
        cmov_bytes(&mut bytes, b"WXYZ", choice_from_bool(false));
        assert_eq!(&bytes, b"abcd");
        cmov_bytes(&mut bytes, b"WXYZ", choice_from_bool(true));
        assert_eq!(&bytes, b"WXYZ");
    }
}
