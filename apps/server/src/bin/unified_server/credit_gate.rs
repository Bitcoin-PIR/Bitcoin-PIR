//! Per-connection gas balance and the admission rule (docs/CREDITS.md
//! "Metering on the server").
//!
//! A balance lives and dies with its connection: credits presented on it
//! top it up, metered frames are charged their work plus base fee before
//! dispatch, and egress is charged after the response is known, so the
//! balance may dip below zero by one response. Nothing carries across
//! connections and nothing is stored, so a client presents exactly what
//! its next round costs.

use std::fmt;

/// Presentations the issuer rejected before the server closes the
/// connection: a client that keeps sending bad tokens costs the issuer a
/// verification each time.
pub(crate) const MAX_PRESENTATION_FAILURES_PER_CONNECTION: u32 = 3;

/// A metered frame the balance cannot cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GasRefusal {
    pub(crate) needed: u64,
    pub(crate) balance: i64,
}

impl fmt::Display for GasRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "insufficient gas: this frame needs {} and the connection has {}; present credits with REQ_CREDIT_PRESENT",
            self.needed, self.balance
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct GasBalanceV1 {
    gas: i64,
    presentation_failures: u32,
}

impl GasBalanceV1 {
    pub(crate) const fn new() -> Self {
        Self {
            gas: 0,
            presentation_failures: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn gas(&self) -> i64 {
        self.gas
    }

    /// Adds the gas a presentation bought; returns the new balance.
    pub(crate) fn top_up(&mut self, gas_added: u64) -> i64 {
        let added = i64::try_from(gas_added).unwrap_or(i64::MAX);
        self.gas = self.gas.saturating_add(added);
        self.gas
    }

    /// Charges a metered frame's work plus base fee, or refuses it (nothing
    /// charged) when the balance does not cover it. A negative balance left
    /// by an earlier egress charge must be covered too.
    pub(crate) fn admit(&mut self, frame_gas: u64) -> Result<i64, GasRefusal> {
        let needed = i64::try_from(frame_gas).unwrap_or(i64::MAX);
        if self.gas < needed {
            return Err(GasRefusal {
                needed: frame_gas,
                balance: self.gas,
            });
        }
        self.gas -= needed;
        Ok(self.gas)
    }

    /// Charges the response bytes of an admitted frame; may go negative.
    pub(crate) fn charge_egress(&mut self, egress_gas: u64) -> i64 {
        let charge = i64::try_from(egress_gas).unwrap_or(i64::MAX);
        self.gas = self.gas.saturating_sub(charge);
        self.gas
    }

    pub(crate) fn note_presentation_failure(&mut self) {
        self.presentation_failures = self.presentation_failures.saturating_add(1);
    }

    pub(crate) fn presentation_failures(&self) -> u32 {
        self.presentation_failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_charged_before_dispatch_and_refused_when_short() {
        let mut b = GasBalanceV1::new();
        assert_eq!(
            b.admit(1_400),
            Err(GasRefusal {
                needed: 1_400,
                balance: 0
            })
        );
        assert_eq!(b.gas(), 0, "a refused frame charges nothing");
        assert_eq!(b.top_up(72_000), 72_000);
        assert_eq!(b.admit(1_400), Ok(70_600));
        assert_eq!(b.admit(4_570), Ok(66_030));
        assert_eq!(
            b.admit(70_000),
            Err(GasRefusal {
                needed: 70_000,
                balance: 66_030
            })
        );
    }

    #[test]
    fn egress_may_leave_a_deficit_that_the_next_top_up_must_cover() {
        let mut b = GasBalanceV1::new();
        b.top_up(1_000);
        assert_eq!(b.admit(1_000), Ok(0));
        assert_eq!(b.charge_egress(4_800), -4_800);
        assert_eq!(
            b.admit(1),
            Err(GasRefusal {
                needed: 1,
                balance: -4_800
            })
        );
        assert_eq!(b.top_up(72_000), 67_200);
        assert_eq!(b.admit(1), Ok(67_199));
    }

    #[test]
    fn arithmetic_saturates_and_failures_are_counted() {
        let mut b = GasBalanceV1::new();
        assert_eq!(b.top_up(u64::MAX), i64::MAX);
        assert_eq!(b.charge_egress(u64::MAX), 0);
        assert_eq!(b.charge_egress(u64::MAX), -i64::MAX);
        assert_eq!(b.presentation_failures(), 0);
        for _ in 0..MAX_PRESENTATION_FAILURES_PER_CONNECTION {
            b.note_presentation_failure();
        }
        assert_eq!(
            b.presentation_failures(),
            MAX_PRESENTATION_FAILURES_PER_CONNECTION
        );
        let refusal = GasRefusal {
            needed: 1_400,
            balance: -7,
        };
        assert_eq!(
            refusal.to_string(),
            "insufficient gas: this frame needs 1400 and the connection has -7; present credits with REQ_CREDIT_PRESENT"
        );
    }
}
