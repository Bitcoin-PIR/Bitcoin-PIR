//! Credits and gas for BitcoinPIR paid queries.
//!
//! Design: `docs/CREDITS.md`. In one sentence: a server meters every
//! request in **gas** (reference-CPU work derived from public database
//! geometry, [`gas`]), the issuer publishes how much gas a **credit** buys
//! ([`params`]), clients pay in credits (Cashu ecash or ARC presentations
//! verified online at the issuer, [`issuer`]), and every server reports an
//! hourly aggregate of what it actually spent ([`meter`]). ARC credentials
//! (epochs, contexts, the kind-2 payload) are fixed in [`arc`].
//!
//! Pure bookkeeping: no cryptography, filesystem, clock, or network.

#![forbid(unsafe_code)]

pub mod arc;
pub mod gas;
pub mod issuer;
pub mod meter;
pub mod params;

pub use gas::{
    Calibration, CuckooGeometry, DatabaseGeometry, GasTable, MeteredOp, OnionGeometry,
    OramGeometry, SubTableGeometry, TableKind, GAS_UNIT,
};
pub use meter::{MeterSample, MeterWindow};
pub use params::GasParams;
