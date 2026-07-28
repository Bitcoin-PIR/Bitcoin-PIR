use std::time::Duration;

use pir_strict_https::{HttpsPostErrorV1, StrictHttpsClientV1};

use crate::{
    ProviderSettlementHttpRequestV1, ProviderSettlementTransportErrorV1,
    ProviderSettlementTransportV1, PROVIDER_BALANCE_ENDPOINT_V1, PROVIDER_PAYOUT_ENDPOINT_V1,
    PROVIDER_PAYOUT_INTENT_ENDPOINT_V1, PROVIDER_PAYOUT_STATUS_ENDPOINT_V1,
};

const CT_BALANCE_ENVELOPE_V1: &str = "application/vnd.bitcoinpir.provider-balance-envelope-v1";
const CT_BALANCE_RESPONSE_V1: &str = "application/vnd.bitcoinpir.issuer-balance-response-v1";
const CT_PAYOUT_INTENT_ENVELOPE_V1: &str =
    "application/vnd.bitcoinpir.provider-payout-intent-envelope-v1";
const CT_PAYOUT_INTENT_RESPONSE_V1: &str =
    "application/vnd.bitcoinpir.issuer-payout-intent-response-v1";
const CT_PAYOUT_ENVELOPE_V1: &str = "application/vnd.bitcoinpir.provider-payout-envelope-v1";
const CT_PAYOUT_RESPONSE_V1: &str = "application/vnd.bitcoinpir.issuer-payout-response-v1";
const CT_PAYOUT_STATUS_ENVELOPE_V1: &str =
    "application/vnd.bitcoinpir.provider-payout-status-envelope-v1";
const CT_PAYOUT_STATUS_RESPONSE_V1: &str =
    "application/vnd.bitcoinpir.issuer-payout-status-response-v1";

/// Production HTTPS adapter for provider settlement operations.
///
/// The underlying client requires WebPKI verification plus one or two
/// out-of-band leaf-SPKI SHA-256 pins and has no redirect, cookie, proxy,
/// decompression, or body-logging support. Each protocol endpoint is pinned to
/// one exact request and response media type. Once any HTTP application byte
/// may have been sent, every transport/parser failure is conservatively
/// reported as an unknown outcome so callers retry only the exact durable
/// operation.
#[derive(Clone, Debug)]
pub struct StrictHttpsProviderSettlementTransportV1 {
    issuer_endpoint: String,
    client: StrictHttpsClientV1,
}

impl StrictHttpsProviderSettlementTransportV1 {
    pub fn new(
        issuer_endpoint: String,
        connect_timeout: Duration,
        io_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<Self, String> {
        StrictHttpsClientV1::validate_base_endpoint(&issuer_endpoint)?;
        // The provider settlement path has no WebPKI-only production mode.
        // Pins add to hostname/chain/time verification; they never replace it.
        let client = StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            connect_timeout,
            io_timeout,
            leaf_spki_sha256_pins,
        )?;
        Ok(Self {
            issuer_endpoint,
            client,
        })
    }

    pub fn issuer_endpoint(&self) -> &str {
        &self.issuer_endpoint
    }
}

impl ProviderSettlementTransportV1 for StrictHttpsProviderSettlementTransportV1 {
    fn post(
        &self,
        request: ProviderSettlementHttpRequestV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, ProviderSettlementTransportErrorV1> {
        let (request_content_type, response_content_type) =
            media_types_for_endpoint_v1(request.endpoint)
                .ok_or(ProviderSettlementTransportErrorV1::NotSent)?;
        self.client
            .post_with_error_content_type(
                &self.issuer_endpoint,
                request.endpoint,
                request_content_type,
                response_content_type,
                "application/problem+json",
                request.canonical_body,
                max_response_bytes,
            )
            .map_err(map_https_error_v1)
    }
}

fn media_types_for_endpoint_v1(endpoint: &str) -> Option<(&'static str, &'static str)> {
    match endpoint {
        PROVIDER_BALANCE_ENDPOINT_V1 => Some((CT_BALANCE_ENVELOPE_V1, CT_BALANCE_RESPONSE_V1)),
        PROVIDER_PAYOUT_INTENT_ENDPOINT_V1 => {
            Some((CT_PAYOUT_INTENT_ENVELOPE_V1, CT_PAYOUT_INTENT_RESPONSE_V1))
        }
        PROVIDER_PAYOUT_ENDPOINT_V1 => Some((CT_PAYOUT_ENVELOPE_V1, CT_PAYOUT_RESPONSE_V1)),
        PROVIDER_PAYOUT_STATUS_ENDPOINT_V1 => {
            Some((CT_PAYOUT_STATUS_ENVELOPE_V1, CT_PAYOUT_STATUS_RESPONSE_V1))
        }
        _ => None,
    }
}

fn map_https_error_v1(error: HttpsPostErrorV1) -> ProviderSettlementTransportErrorV1 {
    match error {
        HttpsPostErrorV1::DefinitelyNotSent => ProviderSettlementTransportErrorV1::NotSent,
        HttpsPostErrorV1::OutcomeUnknown
        | HttpsPostErrorV1::InvalidResponse
        | HttpsPostErrorV1::HttpStatus { .. } => ProviderSettlementTransportErrorV1::OutcomeUnknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn every_settlement_route_has_exact_distinct_media_types() {
        assert_eq!(
            media_types_for_endpoint_v1(PROVIDER_BALANCE_ENDPOINT_V1),
            Some((CT_BALANCE_ENVELOPE_V1, CT_BALANCE_RESPONSE_V1))
        );
        assert_eq!(
            media_types_for_endpoint_v1(PROVIDER_PAYOUT_INTENT_ENDPOINT_V1),
            Some((CT_PAYOUT_INTENT_ENVELOPE_V1, CT_PAYOUT_INTENT_RESPONSE_V1))
        );
        assert_eq!(
            media_types_for_endpoint_v1(PROVIDER_PAYOUT_ENDPOINT_V1),
            Some((CT_PAYOUT_ENVELOPE_V1, CT_PAYOUT_RESPONSE_V1))
        );
        assert_eq!(
            media_types_for_endpoint_v1(PROVIDER_PAYOUT_STATUS_ENDPOINT_V1),
            Some((CT_PAYOUT_STATUS_ENVELOPE_V1, CT_PAYOUT_STATUS_RESPONSE_V1))
        );
        assert_eq!(media_types_for_endpoint_v1("/v1/settlement/other"), None);
    }

    #[test]
    fn transport_outcomes_preserve_exact_retry_boundary() {
        assert_eq!(
            map_https_error_v1(HttpsPostErrorV1::DefinitelyNotSent),
            ProviderSettlementTransportErrorV1::NotSent
        );
        assert_eq!(
            map_https_error_v1(HttpsPostErrorV1::HttpStatus {
                status: 409,
                body: Zeroizing::new(Vec::new()),
            }),
            ProviderSettlementTransportErrorV1::OutcomeUnknown
        );
        assert_eq!(
            map_https_error_v1(HttpsPostErrorV1::OutcomeUnknown),
            ProviderSettlementTransportErrorV1::OutcomeUnknown
        );
        assert_eq!(
            map_https_error_v1(HttpsPostErrorV1::HttpStatus {
                status: 503,
                body: Zeroizing::new(Vec::new()),
            }),
            ProviderSettlementTransportErrorV1::OutcomeUnknown
        );
        assert_eq!(
            map_https_error_v1(HttpsPostErrorV1::InvalidResponse),
            ProviderSettlementTransportErrorV1::OutcomeUnknown
        );
    }

    #[test]
    fn every_unsigned_http_status_is_outcome_unknown() {
        // HTTP status and error bodies are unsigned transport artifacts. Even
        // a syntactically ordinary 4xx can arrive after the issuer committed
        // the exact mutation, so no u16 status is a definite rejection here.
        for status in 0..=u16::MAX {
            assert_eq!(
                map_https_error_v1(HttpsPostErrorV1::HttpStatus {
                    status,
                    body: Zeroizing::new(Vec::new()),
                }),
                ProviderSettlementTransportErrorV1::OutcomeUnknown
            );
        }
    }

    #[test]
    fn constructor_rejects_noncanonical_or_non_https_endpoints() {
        for endpoint in [
            "http://issuer.example",
            "https://issuer.example/",
            "https://user@issuer.example",
            "https://issuer.example?query",
        ] {
            assert!(StrictHttpsProviderSettlementTransportV1::new(
                endpoint.to_owned(),
                Duration::from_secs(1),
                Duration::from_secs(1),
                &[[1; 32]],
            )
            .is_err());
        }
        assert!(StrictHttpsProviderSettlementTransportV1::new(
            "https://issuer.example/api".to_owned(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            &[[1; 32]],
        )
        .is_ok());
        for pins in [
            &[][..],
            &[[1; 32], [1; 32]][..],
            &[[1; 32], [2; 32], [3; 32]][..],
        ] {
            assert!(StrictHttpsProviderSettlementTransportV1::new(
                "https://issuer.example/api".to_owned(),
                Duration::from_secs(1),
                Duration::from_secs(1),
                pins,
            )
            .is_err());
        }
    }
}
