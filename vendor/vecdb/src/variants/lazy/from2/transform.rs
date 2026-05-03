use std::ops::{Add, Div, Mul, Sub};

/// Trait for binary transforms applied lazily during iteration.
/// Zero-sized types implementing this get monomorphized (zero runtime cost).
pub trait BinaryTransform<In1, In2, Out = In1> {
    fn apply(lhs: In1, rhs: In2) -> Out;
}

/// (a, b) -> a / b
pub struct Divide;

impl<T: Div<U, Output = O>, U, O> BinaryTransform<T, U, O> for Divide {
    #[inline(always)]
    fn apply(lhs: T, rhs: U) -> O {
        lhs / rhs
    }
}

/// (a, b) -> a + b
pub struct Plus;

impl<T: Add<U, Output = O>, U, O> BinaryTransform<T, U, O> for Plus {
    #[inline(always)]
    fn apply(lhs: T, rhs: U) -> O {
        lhs + rhs
    }
}

/// (a, b) -> a - b
pub struct Minus;

impl<T: Sub<U, Output = O>, U, O> BinaryTransform<T, U, O> for Minus {
    #[inline(always)]
    fn apply(lhs: T, rhs: U) -> O {
        lhs - rhs
    }
}

/// (a, b) -> a * b
pub struct Times;

impl<T: Mul<U, Output = O>, U, O> BinaryTransform<T, U, O> for Times {
    #[inline(always)]
    fn apply(lhs: T, rhs: U) -> O {
        lhs * rhs
    }
}
