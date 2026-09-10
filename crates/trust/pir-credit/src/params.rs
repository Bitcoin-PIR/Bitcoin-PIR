//! Issuer-published parameters that turn gas into credits, and the
//! credit ↔ sat ↔ gas arithmetic every party must agree on.

use serde::{Deserialize, Serialize};

/// The parameters the issuer publishes in `GET /v1/info` and a server
/// meters with. Changing any of them changes prices for every client of
/// that issuer, so they are versioned by publication, not by code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasParams {
    /// Satoshis one credit costs (and the sat value of one ARC
    /// presentation). Cashu proofs convert at `gas_per_credit / credit_sat`
    /// gas per sat, so a proof of any amount can be presented.
    pub credit_sat: u64,
    /// Gas one credit buys. The single knob that anchors prices to a fiat
    /// target: raise it when BTC falls, lower it when BTC rises.
    pub gas_per_credit: u64,
    /// Gas charged for every metered frame on top of its work, covering the
    /// per-request overhead (frame handling, channel crypto, the issuer
    /// round trip amortised over the frames a top-up serves).
    pub base_gas_per_frame: u64,
    /// Gas charged per 1,000,000 response bytes, so a provider that pays
    /// for egress can price it. Charged after the response is known.
    pub egress_gas_per_mb: u64,
}

impl GasParams {
    /// The parameter set chosen on 2026-09-09 (docs/CREDITS.md "Rate card"):
    /// one credit is 10 sat, a single OnionPIR lookup lands on 10 credits,
    /// a fresh HarmonyPIR client on 5, a single DPF lookup on 2, an ORAM
    /// lookup on 1.
    pub const PRODUCTION_2026_09: GasParams = GasParams {
        credit_sat: 10,
        gas_per_credit: 72_000,
        base_gas_per_frame: 20,
        egress_gas_per_mb: 1_000,
    };

    /// Rejects parameter sets that would divide by zero or price nothing.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.credit_sat == 0 {
            return Err("credit_sat must be at least 1");
        }
        if self.gas_per_credit == 0 {
            return Err("gas_per_credit must be at least 1");
        }
        Ok(())
    }

    /// Gas a metered frame costs before its response is known: its work
    /// plus the base fee.
    pub fn frame_gas(&self, work_gas: u64) -> u64 {
        work_gas.saturating_add(self.base_gas_per_frame)
    }

    /// Gas charged for `response_bytes` of egress (rounded down).
    pub fn egress_gas(&self, response_bytes: u64) -> u64 {
        let gas = u128::from(response_bytes) * u128::from(self.egress_gas_per_mb) / 1_000_000;
        u64::try_from(gas).unwrap_or(u64::MAX)
    }

    /// Gas `credits` credits buy.
    pub fn credits_to_gas(&self, credits: u64) -> u64 {
        credits.saturating_mul(self.gas_per_credit)
    }

    /// Gas `sats` of ecash buy: `sats * gas_per_credit / credit_sat`,
    /// rounded down.
    pub fn sats_to_gas(&self, sats: u64) -> u64 {
        let gas = u128::from(sats) * u128::from(self.gas_per_credit) / u128::from(self.credit_sat);
        u64::try_from(gas).unwrap_or(u64::MAX)
    }

    /// Whole credits needed to cover `gas` (rounded up).
    pub fn credits_to_cover(&self, gas: u64) -> u64 {
        gas.div_ceil(self.gas_per_credit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_parameters_validate_and_convert() {
        let p = GasParams::PRODUCTION_2026_09;
        p.validate().unwrap();
        assert_eq!(p.frame_gas(1_380), 1_400);
        assert_eq!(p.egress_gas(131_000_000), 131_000);
        assert_eq!(p.egress_gas(999_999), 999);
        assert_eq!(p.credits_to_gas(10), 720_000);
        assert_eq!(p.sats_to_gas(10), 72_000);
        assert_eq!(p.credits_to_cover(0), 0);
        assert_eq!(p.credits_to_cover(1), 1);
        assert_eq!(p.credits_to_cover(72_000), 1);
        assert_eq!(p.credits_to_cover(72_001), 2);
    }

    #[test]
    fn zero_parameters_are_rejected() {
        let mut p = GasParams::PRODUCTION_2026_09;
        p.credit_sat = 0;
        assert!(p.validate().is_err());
        let mut p = GasParams::PRODUCTION_2026_09;
        p.gas_per_credit = 0;
        assert!(p.validate().is_err());
    }

    #[test]
    fn conversions_saturate_instead_of_overflowing() {
        let p = GasParams::PRODUCTION_2026_09;
        assert_eq!(p.credits_to_gas(u64::MAX), u64::MAX);
        assert_eq!(p.frame_gas(u64::MAX), u64::MAX);
        assert_eq!(p.sats_to_gas(u64::MAX), u64::MAX);
        assert_eq!(p.egress_gas(u64::MAX), u64::MAX / 1_000);
    }

    #[test]
    fn serde_round_trip_is_stable() {
        let p = GasParams::PRODUCTION_2026_09;
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"credit_sat":10,"gas_per_credit":72000,"base_gas_per_frame":20,"egress_gas_per_mb":1000}"#
        );
        assert_eq!(serde_json::from_str::<GasParams>(&json).unwrap(), p);
    }
}
