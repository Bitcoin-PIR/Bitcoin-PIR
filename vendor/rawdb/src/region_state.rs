use std::sync::atomic::{AtomicU8, Ordering};

/// State transitions: NEEDS_WRITE → NEEDS_FLUSH → IS_CLEAN.
#[derive(Debug)]
pub struct RegionState(AtomicU8);

impl RegionState {
    pub const IS_CLEAN: u8 = 0;
    pub const NEEDS_FLUSH: u8 = 1;
    pub const NEEDS_WRITE: u8 = 2;

    #[inline(always)]
    pub fn new_dirty() -> Self {
        Self(AtomicU8::new(Self::NEEDS_WRITE))
    }

    #[inline(always)]
    pub fn new_clean() -> Self {
        Self(AtomicU8::new(Self::IS_CLEAN))
    }

    #[inline(always)]
    fn load(&self) -> u8 {
        self.0.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn is_clean(&self) -> bool {
        self.load() == Self::IS_CLEAN
    }

    #[inline(always)]
    pub fn set_is_clean(&self) {
        self.0.store(Self::IS_CLEAN, Ordering::Release);
    }

    #[inline(always)]
    pub fn needs_flush(&self) -> bool {
        self.load() == Self::NEEDS_FLUSH
    }

    #[inline(always)]
    pub fn set_needs_flush(&self) {
        self.0.store(Self::NEEDS_FLUSH, Ordering::Release);
    }

    #[inline(always)]
    pub fn needs_write(&self) -> bool {
        self.load() == Self::NEEDS_WRITE
    }

    #[inline(always)]
    pub fn set_needs_write(&self) {
        self.0.store(Self::NEEDS_WRITE, Ordering::Release);
    }
}
