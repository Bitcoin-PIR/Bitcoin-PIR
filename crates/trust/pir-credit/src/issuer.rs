//! JSON types of the issuer HTTP contract (docs/CREDITS.md "Issuer API")
//! and the canonical signing preimage of a redeem request. Shared by the
//! PIR server (client of `/v1/redeem`) and the issuer implementation.

use serde::{Deserialize, Serialize};

/// `GET /v1/info` version that carries gas parameters.
pub const ISSUER_API_VERSION: u32 = 2;
/// `REQ_CREDIT_PRESENT` kind byte: a Cashu token (proofs in sat).
pub const CREDIT_PRESENT_KIND_CASHU: u8 = 1;
/// `REQ_CREDIT_PRESENT` kind byte: one or more ARC presentations.
pub const CREDIT_PRESENT_KIND_ARC: u8 = 2;
/// Domain separation prefix of a redeem request's signing preimage.
pub const REDEEM_SIGNING_DOMAIN_V1: &[u8] = b"BPIR-CREDIT-REDEEM-V1";
/// Domain separation prefix of a redeem response's signing preimage.
pub const REDEEM_RESPONSE_SIGNING_DOMAIN_V1: &[u8] = b"BPIR-CREDIT-REDEEM-RESPONSE-V1";
/// Length of the per-request nonce a server draws.
pub const REDEEM_NONCE_LEN: usize = 16;

/// One purchasable pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferV2 {
    pub credits: u64,
    pub sat: u64,
}

/// ARC issuance parameters of the current epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcInfoV2 {
    pub epoch: u32,
    /// Presentations one credential allows (one credit each).
    pub presentation_limit: u32,
    pub issuer_public_key_hex: String,
    pub presentation_context_hex: String,
    /// Unix seconds after which the epoch's credentials are refused.
    pub valid_until: u64,
}

/// Informational worst-case prices the issuer publishes next to the
/// parameters they follow from (`flow` is a free-form label).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCardEntryV2 {
    pub flow: String,
    pub credits: u64,
}

/// `GET /v1/info`, version 2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerInfoV2 {
    pub service: String,
    pub version: u32,
    pub credit_sat: u64,
    pub gas_per_credit: u64,
    pub base_gas_per_frame: u64,
    pub egress_gas_per_mb: u64,
    #[serde(default)]
    pub mints: Vec<String>,
    #[serde(default)]
    pub offers: Vec<OfferV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arc: Option<ArcInfoV2>,
    #[serde(default)]
    pub rate_card: Vec<RateCardEntryV2>,
}

impl IssuerInfoV2 {
    pub fn gas_params(&self) -> crate::params::GasParams {
        crate::params::GasParams {
            credit_sat: self.credit_sat,
            gas_per_credit: self.gas_per_credit,
            base_gas_per_frame: self.base_gas_per_frame,
            egress_gas_per_mb: self.egress_gas_per_mb,
        }
    }
}

/// One presented item forwarded verbatim (payload as lowercase hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemItemV1 {
    pub kind: u8,
    pub payload_hex: String,
}

/// `POST /v1/redeem`: a server asks the issuer to verify what a client
/// presented and to credit the server's settlement account. Signed with
/// the server's identity key; the issuer pins the operator keys that may
/// certify server identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemRequestV1 {
    pub server_id: String,
    /// The operator-signed identity certificate (`IdentityCert::encode`,
    /// lowercase hex); the issuer pins the operator keys that may sign it.
    pub identity_cert_hex: String,
    /// 16 random bytes; the issuer answers a repeated `(server_id, nonce)`
    /// with the stored response instead of verifying again.
    pub nonce_hex: String,
    pub unix_time: u64,
    pub items: Vec<RedeemItemV1>,
    /// Ed25519 signature over [`RedeemRequestV1::signing_preimage`].
    pub signature_hex: String,
}

impl RedeemRequestV1 {
    /// Bytes the server signs and the issuer verifies:
    /// domain ‖ len(server_id) u16 ‖ server_id ‖ nonce ‖ unix_time u64 ‖
    /// count u32 ‖ (kind u8 ‖ len u32 ‖ payload)*, all little-endian.
    pub fn signing_preimage(
        server_id: &str,
        nonce: &[u8; REDEEM_NONCE_LEN],
        unix_time: u64,
        items: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            REDEEM_SIGNING_DOMAIN_V1.len()
                + 2
                + server_id.len()
                + REDEEM_NONCE_LEN
                + 8
                + 4
                + items.iter().map(|(_, p)| 5 + p.len()).sum::<usize>(),
        );
        out.extend_from_slice(REDEEM_SIGNING_DOMAIN_V1);
        out.extend_from_slice(&(server_id.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id.as_bytes());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&unix_time.to_le_bytes());
        out.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for (kind, payload) in items {
            out.push(*kind);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        out
    }
}

/// `POST /v1/redeem` success body. Signed by the issuer's Ed25519 key (the
/// same key the servers pin for session grants), bound to the request
/// nonce, so a CDN or proxy between server and issuer cannot forge gas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemResponseV1 {
    /// Gas the server credits the presenting connection.
    pub gas_added: u64,
    /// Sat value the issuer booked to the server's settlement account.
    pub sat_value: u64,
    pub items_accepted: u32,
    /// Ed25519 signature over [`RedeemResponseV1::signing_preimage`].
    pub issuer_signature_hex: String,
}

impl RedeemResponseV1 {
    /// Bytes the issuer signs and the server verifies:
    /// domain ‖ request nonce ‖ gas_added u64 ‖ sat_value u64 ‖
    /// items_accepted u32, little-endian.
    pub fn signing_preimage(
        nonce: &[u8; REDEEM_NONCE_LEN],
        gas_added: u64,
        sat_value: u64,
        items_accepted: u32,
    ) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(REDEEM_RESPONSE_SIGNING_DOMAIN_V1.len() + REDEEM_NONCE_LEN + 20);
        out.extend_from_slice(REDEEM_RESPONSE_SIGNING_DOMAIN_V1);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&gas_added.to_le_bytes());
        out.extend_from_slice(&sat_value.to_le_bytes());
        out.extend_from_slice(&items_accepted.to_le_bytes());
        out
    }
}

/// Error body shared by every issuer endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerErrorV1 {
    pub error: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_round_trips_and_tolerates_absent_optional_sections() {
        let info = IssuerInfoV2 {
            service: "bitcoinpir-issuer".into(),
            version: ISSUER_API_VERSION,
            credit_sat: 10,
            gas_per_credit: 72_000,
            base_gas_per_frame: 20,
            egress_gas_per_mb: 1_000,
            mints: vec!["https://mint.example".into()],
            offers: vec![OfferV2 {
                credits: 100,
                sat: 1_000,
            }],
            arc: None,
            rate_card: vec![RateCardEntryV2 {
                flow: "onion_single_address".into(),
                credits: 10,
            }],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("\"arc\""));
        assert_eq!(serde_json::from_str::<IssuerInfoV2>(&json).unwrap(), info);
        assert_eq!(
            info.gas_params(),
            crate::params::GasParams::PRODUCTION_2026_09
        );
        let minimal = r#"{"service":"x","version":2,"credit_sat":10,"gas_per_credit":72000,"base_gas_per_frame":20,"egress_gas_per_mb":1000}"#;
        let parsed = serde_json::from_str::<IssuerInfoV2>(minimal).unwrap();
        assert!(parsed.mints.is_empty() && parsed.offers.is_empty() && parsed.rate_card.is_empty());
    }

    #[test]
    fn redeem_preimage_is_canonical_and_length_prefixed() {
        let nonce = [7u8; REDEEM_NONCE_LEN];
        let a = RedeemRequestV1::signing_preimage(
            "pir1",
            &nonce,
            1_800_000_000,
            &[(1, b"ab"), (2, b"c")],
        );
        let b = RedeemRequestV1::signing_preimage(
            "pir1",
            &nonce,
            1_800_000_000,
            &[(1, b"ab"), (2, b"c")],
        );
        assert_eq!(a, b);
        let mut expected = REDEEM_SIGNING_DOMAIN_V1.to_vec();
        expected.extend_from_slice(&4u16.to_le_bytes());
        expected.extend_from_slice(b"pir1");
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&1_800_000_000u64.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[1, 2, 0, 0, 0, b'a', b'b', 2, 1, 0, 0, 0, b'c']);
        assert_eq!(a, expected);
        // Moving a byte across the item boundary changes the preimage.
        let c = RedeemRequestV1::signing_preimage(
            "pir1",
            &nonce,
            1_800_000_000,
            &[(1, b"a"), (2, b"bc")],
        );
        assert_ne!(a, c);
        let d = RedeemRequestV1::signing_preimage(
            "pir2",
            &nonce,
            1_800_000_000,
            &[(1, b"ab"), (2, b"c")],
        );
        assert_ne!(a, d);
    }

    #[test]
    fn redeem_bodies_round_trip() {
        let request = RedeemRequestV1 {
            server_id: "pir2".into(),
            identity_cert_hex: "000102".into(),
            nonce_hex: "00".repeat(REDEEM_NONCE_LEN),
            unix_time: 1,
            items: vec![RedeemItemV1 {
                kind: CREDIT_PRESENT_KIND_ARC,
                payload_hex: "010203".into(),
            }],
            signature_hex: "ff".repeat(64),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<RedeemRequestV1>(&json).unwrap(),
            request
        );
        let response = RedeemResponseV1 {
            gas_added: 72_000,
            sat_value: 10,
            items_accepted: 1,
            issuer_signature_hex: "00".repeat(64),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"gas_added":72000,"sat_value":10,"items_accepted":1,"issuer_signature_hex":"{}"}}"#,
                "00".repeat(64)
            )
        );
        let nonce = [3u8; REDEEM_NONCE_LEN];
        let mut expected = REDEEM_RESPONSE_SIGNING_DOMAIN_V1.to_vec();
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&72_000u64.to_le_bytes());
        expected.extend_from_slice(&10u64.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            RedeemResponseV1::signing_preimage(&nonce, 72_000, 10, 1),
            expected
        );
        let error: IssuerErrorV1 =
            serde_json::from_str(r#"{"error":"double_spend","message":"tag seen"}"#).unwrap();
        assert_eq!(error.error, "double_spend");
    }
}
