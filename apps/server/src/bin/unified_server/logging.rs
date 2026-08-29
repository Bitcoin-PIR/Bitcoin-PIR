//! Privacy-gated query logging macros. Defined here so sibling modules can
//! import them.

#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
use std::sync::atomic::AtomicBool;

#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
pub(crate) static UNSAFE_DEBUG_QUERY_LOGGING: AtomicBool = AtomicBool::new(false);

/// Detailed per-connection/per-query logging is a privacy-dangerous local
/// diagnostic mode. Production/default logging must never depend on request
/// identity, shape, selected database, byte count, or elapsed time.
#[cfg(any(test, feature = "test-only-unsafe-query-logging"))]
macro_rules! unsafe_debug_log {
    ($($arg:tt)*) => {
        if crate::UNSAFE_DEBUG_QUERY_LOGGING
            .load(::std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!($($arg)*);
        }
    };
}

/// Build a query-derived ORAM diagnostic only in an explicitly unsafe local
/// diagnostic build *and* only when its runtime switch is enabled. In normal
/// artifacts the formatting expression (including bin/chunk identifiers and
/// backend error text) is not compiled at all.
#[cfg(all(
    feature = "cuckoo-oram",
    any(test, feature = "test-only-unsafe-query-logging")
))]
macro_rules! unsafe_oram_detail {
    ($($arg:tt)*) => {{
        if crate::UNSAFE_DEBUG_QUERY_LOGGING
            .load(::std::sync::atomic::Ordering::Relaxed)
        {
            Some(format!($($arg)*))
        } else {
            None
        }
    }};
}

#[cfg(all(
    feature = "cuckoo-oram",
    not(any(test, feature = "test-only-unsafe-query-logging"))
))]
macro_rules! unsafe_oram_detail {
    ($($arg:tt)*) => {{
        None::<String>
    }};
}

// Keep call sites type-checked and their timing variables non-unused without
// compiling an output path or runtime switch into normal binaries.
#[cfg(not(any(test, feature = "test-only-unsafe-query-logging")))]
macro_rules! unsafe_debug_log {
    ($($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

pub(crate) use unsafe_debug_log;
#[cfg(feature = "cuckoo-oram")]
pub(crate) use unsafe_oram_detail;
