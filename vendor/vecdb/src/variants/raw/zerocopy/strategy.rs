use std::marker::PhantomData;

use crate::{Error, Result, ValueStrategy, ZeroCopyVecValue, variants::raw::RawStrategy};

/// Serialization strategy using zerocopy for native byte order access.
///
/// Uses direct memory mapping in native byte order - not portable across endianness.
#[derive(Debug, Clone, Copy)]
pub struct ZeroCopyStrategy<T>(PhantomData<T>);

impl<T: ZeroCopyVecValue> ValueStrategy<T> for ZeroCopyStrategy<T> {
    const IS_NATIVE_LAYOUT: bool = true;

    #[inline(always)]
    fn read(bytes: &[u8]) -> Result<T> {
        T::read_from_prefix(bytes)
            .map(|(v, _)| v)
            .map_err(|_| Error::ZeroCopyError)
    }

    #[inline(always)]
    fn write_to_vec(value: &T, buf: &mut Vec<u8>) {
        buf.extend_from_slice(value.as_bytes());
    }

    #[inline(always)]
    fn write_to_slice(value: &T, dst: &mut [u8]) {
        dst.copy_from_slice(value.as_bytes());
    }
}

impl<T: ZeroCopyVecValue> RawStrategy<T> for ZeroCopyStrategy<T> {
    #[inline(always)]
    unsafe fn read_from_ptr(ptr: *const u8, byte_offset: usize) -> T {
        unsafe { (ptr.add(byte_offset) as *const T).read_unaligned() }
    }
}
