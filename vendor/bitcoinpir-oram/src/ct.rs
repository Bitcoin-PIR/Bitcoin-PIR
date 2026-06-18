//! Small constant-shape selection helpers.
//!
//! These helpers make the ORAM hot loops easier to audit. They are not a
//! substitute for inspecting optimized assembly on the SEV-SNP target.

/// A one-bit choice value.
pub type Choice = u8;

/// Normalize a bool into a one-bit choice.
#[inline]
pub const fn choice_from_bool(value: bool) -> Choice {
    value as Choice
}

/// Return `1 - choice` for one-bit choices.
#[inline]
pub const fn not(choice: Choice) -> Choice {
    (choice ^ 1) & 1
}

/// Return `lhs & rhs` for one-bit choices.
#[inline]
pub const fn and(lhs: Choice, rhs: Choice) -> Choice {
    (lhs & rhs) & 1
}

/// Return `lhs | rhs` for one-bit choices.
#[inline]
pub const fn or(lhs: Choice, rhs: Choice) -> Choice {
    (lhs | rhs) & 1
}

/// Convert a choice into an all-zero or all-one byte mask.
#[inline]
pub const fn mask8(choice: Choice) -> u8 {
    0u8.wrapping_sub(choice & 1)
}

/// Convert a choice into an all-zero or all-one u32 mask.
#[inline]
pub const fn mask32(choice: Choice) -> u32 {
    0u32.wrapping_sub((choice & 1) as u32)
}

/// Convert a choice into an all-zero or all-one u64 mask.
#[inline]
pub const fn mask64(choice: Choice) -> u64 {
    0u64.wrapping_sub((choice & 1) as u64)
}

/// Constant-shape `value == 0` for u64.
#[inline]
pub const fn is_zero_u64(value: u64) -> Choice {
    let nonzero = (value | value.wrapping_neg()) >> 63;
    (nonzero as Choice) ^ 1
}

/// Constant-shape equality for u64.
#[inline]
pub const fn eq_u64(lhs: u64, rhs: u64) -> Choice {
    is_zero_u64(lhs ^ rhs)
}

/// Constant-shape equality for u32.
#[inline]
pub const fn eq_u32(lhs: u32, rhs: u32) -> Choice {
    is_zero_u64((lhs ^ rhs) as u64)
}

/// Constant-shape equality for usize.
#[inline]
pub const fn eq_usize(lhs: usize, rhs: usize) -> Choice {
    is_zero_u64((lhs ^ rhs) as u64)
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_u8(dst: &mut u8, src: u8, choice: Choice) {
    let mask = mask8(choice);
    *dst ^= (*dst ^ src) & mask;
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_u32(dst: &mut u32, src: u32, choice: Choice) {
    let mask = mask32(choice);
    *dst ^= (*dst ^ src) & mask;
}

/// Conditionally assign `src` to `dst`.
#[inline]
pub fn cmov_u64(dst: &mut u64, src: u64, choice: Choice) {
    let mask = mask64(choice);
    *dst ^= (*dst ^ src) & mask;
}

/// Conditionally copy `src` into `dst`.
#[inline]
pub fn cmov_bytes(dst: &mut [u8], src: &[u8], choice: Choice) {
    debug_assert_eq!(dst.len(), src.len());
    let mask = mask8(choice);
    for (dst, src) in dst.iter_mut().zip(src.iter()) {
        *dst ^= (*dst ^ *src) & mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_helpers_work() {
        assert_eq!(eq_u64(7, 7), 1);
        assert_eq!(eq_u64(7, 8), 0);
        assert_eq!(eq_u32(9, 9), 1);
        assert_eq!(eq_u32(9, 10), 0);
        assert_eq!(eq_usize(11, 11), 1);
        assert_eq!(eq_usize(11, 12), 0);
    }

    #[test]
    fn cmov_helpers_select() {
        let mut word = 1u64;
        cmov_u64(&mut word, 7, 0);
        assert_eq!(word, 1);
        cmov_u64(&mut word, 7, 1);
        assert_eq!(word, 7);

        let mut bytes = *b"abcd";
        cmov_bytes(&mut bytes, b"WXYZ", 0);
        assert_eq!(&bytes, b"abcd");
        cmov_bytes(&mut bytes, b"WXYZ", 1);
        assert_eq!(&bytes, b"WXYZ");
    }
}
