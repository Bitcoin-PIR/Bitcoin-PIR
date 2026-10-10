//! Query logging macros. Defined here so sibling modules can import them.
//!
//! Per-connection/per-query logs expose request identity, shape, database,
//! byte counts and timing, so they exist only in builds with the
//! `test-only-unsafe-query-logging` feature. Normal builds compile the call
//! sites for type checking but contain no output path.

#[cfg(feature = "test-only-unsafe-query-logging")]
macro_rules! unsafe_debug_log {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

#[cfg(not(feature = "test-only-unsafe-query-logging"))]
macro_rules! unsafe_debug_log {
    ($($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

/// A query-derived ORAM diagnostic (bin/chunk identifiers, backend error
/// text), built only in `test-only-unsafe-query-logging` builds.
#[cfg(all(feature = "cuckoo-oram", feature = "test-only-unsafe-query-logging"))]
macro_rules! unsafe_oram_detail {
    ($($arg:tt)*) => {{
        Some(format!($($arg)*))
    }};
}

#[cfg(all(
    feature = "cuckoo-oram",
    not(feature = "test-only-unsafe-query-logging")
))]
macro_rules! unsafe_oram_detail {
    ($($arg:tt)*) => {{
        None::<String>
    }};
}

pub(crate) use unsafe_debug_log;
#[cfg(feature = "cuckoo-oram")]
pub(crate) use unsafe_oram_detail;
