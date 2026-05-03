use std::ops::{Div, Neg};

/// Trait for unary transforms applied lazily during iteration.
/// Zero-sized types implementing this get monomorphized (zero runtime cost).
pub trait UnaryTransform<In, Out = In> {
    fn apply(value: In) -> Out;
}

/// v -> v
pub struct Ident;

impl<T> UnaryTransform<T> for Ident {
    #[inline(always)]
    fn apply(value: T) -> T {
        value
    }
}

/// v -> -v
pub struct Negate;

impl<T: Neg<Output = T>> UnaryTransform<T> for Negate {
    #[inline(always)]
    fn apply(value: T) -> T {
        -value
    }
}

/// v -> v / 2
pub struct Halve;

impl<T: Div<i64, Output = T>> UnaryTransform<T> for Halve {
    #[inline(always)]
    fn apply(value: T) -> T {
        value / 2
    }
}
