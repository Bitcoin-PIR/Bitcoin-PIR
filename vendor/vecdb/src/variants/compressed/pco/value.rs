use std::mem::{ManuallyDrop, align_of, size_of};

use pco::data_types::Number;

use crate::{BytesVecValue, Pco, TransparentPco};

pub trait PcoVecValue: Pco + BytesVecValue + Copy {}

impl<T> PcoVecValue for T where T: Pco + BytesVecValue + Copy {}

/// Convert a slice of PcoVecValue to a slice of the underlying Number type.
///
/// # Safety
/// This trait uses unsafe pointer casting that relies on compile-time size/alignment checks.
/// The const assertions ensure T and T::NumberType have identical layout.
pub trait AsInnerSlice<T>
where
    T: Number,
{
    const _SIZE_CHECK: ();
    const _ALIGN_CHECK: ();

    fn as_inner_slice(&self) -> &[T];
}

impl<T> AsInnerSlice<T::NumberType> for [T]
where
    T: PcoVecValue,
{
    const _SIZE_CHECK: () = assert!(size_of::<T>() == size_of::<T::NumberType>());
    const _ALIGN_CHECK: () = assert!(align_of::<T>() == align_of::<T::NumberType>());

    fn as_inner_slice(&self) -> &[T::NumberType] {
        // SAFETY: Compile-time assertions ensure T and T::NumberType have identical layout
        unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T::NumberType, self.len()) }
    }
}

/// Convert a mutable slice of PcoVecValue to a mutable slice of the underlying Number type.
///
/// # Safety
/// This trait uses unsafe pointer casting that relies on compile-time size/alignment checks.
/// The const assertions ensure T and T::NumberType have identical layout.
pub trait AsInnerSliceMut<T>
where
    T: Number,
{
    const _SIZE_CHECK: ();
    const _ALIGN_CHECK: ();

    fn as_inner_slice_mut(&mut self) -> &mut [T];
}

impl<T> AsInnerSliceMut<T::NumberType> for [T]
where
    T: PcoVecValue,
{
    const _SIZE_CHECK: () = assert!(size_of::<T>() == size_of::<T::NumberType>());
    const _ALIGN_CHECK: () = assert!(align_of::<T>() == align_of::<T::NumberType>());

    fn as_inner_slice_mut(&mut self) -> &mut [T::NumberType] {
        // SAFETY: Compile-time assertions ensure T and T::NumberType have identical layout
        unsafe {
            std::slice::from_raw_parts_mut(self.as_mut_ptr() as *mut T::NumberType, self.len())
        }
    }
}

/// Convert a Vec of Number type to a Vec of PcoVecValue.
///
/// # Safety
/// This trait uses unsafe pointer casting that relies on compile-time size/alignment checks.
/// The const assertions ensure T and T::NumberType have identical layout.
pub trait FromInnerSlice<T> {
    const _SIZE_CHECK: ();
    const _ALIGN_CHECK: ();

    fn from_inner_slice(slice: Vec<T>) -> Vec<Self>
    where
        Self: Sized;
}

impl<T> FromInnerSlice<T::NumberType> for T
where
    T: PcoVecValue,
{
    const _SIZE_CHECK: () = assert!(size_of::<T>() == size_of::<T::NumberType>());
    const _ALIGN_CHECK: () = assert!(align_of::<T>() == align_of::<T::NumberType>());

    fn from_inner_slice(vec: Vec<T::NumberType>) -> Vec<T> {
        let mut vec = ManuallyDrop::new(vec);
        unsafe { Vec::from_raw_parts(vec.as_mut_ptr() as *mut T, vec.len(), vec.capacity()) }
    }
}

macro_rules! impl_stored_compressed {
    ($($t:ty),*) => {
        $(
            impl TransparentPco<$t> for $t {}
            impl Pco for $t {
                type NumberType = $t;
            }
        )*
    };
}

impl_stored_compressed!(u8, u16, u32, u64, i8, i16, i32, i64, f32, f64);
