use std::marker::PhantomData;

use crate::{BytesVecValue, Result, ValueStrategy, variants::raw::RawStrategy};

/// Serialization strategy using the Bytes trait with portable byte order.
///
/// Implements little-endian serialization for cross-platform compatibility.
#[derive(Debug, Clone, Copy)]
pub struct BytesStrategy<T>(PhantomData<T>);

impl<T: BytesVecValue> ValueStrategy<T> for BytesStrategy<T> {
    const IS_NATIVE_LAYOUT: bool = T::IS_NATIVE_LAYOUT;

    #[inline(always)]
    fn read(bytes: &[u8]) -> Result<T> {
        T::from_bytes(bytes)
    }

    #[inline(always)]
    fn write_to_vec(value: &T, buf: &mut Vec<u8>) {
        buf.extend_from_slice(value.to_bytes().as_ref());
    }

    #[inline(always)]
    fn write_to_slice(value: &T, dst: &mut [u8]) {
        dst.copy_from_slice(value.to_bytes().as_ref());
    }
}

impl<T: BytesVecValue> RawStrategy<T> for BytesStrategy<T> {
    #[inline(always)]
    unsafe fn read_from_ptr(ptr: *const u8, byte_offset: usize) -> T {
        unsafe {
            if T::IS_NATIVE_LAYOUT {
                (ptr.add(byte_offset) as *const T).read_unaligned()
            } else {
                let slice = std::slice::from_raw_parts(ptr.add(byte_offset), size_of::<T>());
                Self::read(slice).unwrap_unchecked()
            }
        }
    }
}
