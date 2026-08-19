use std::time::Duration;

use pir_strict_https::{HttpsPostErrorV1, StrictHttpsClientV1};

use crate::{
    BatV2RedeemHttpRequestV2, BatV2RedeemTransportErrorV2, BatV2RedeemTransportV2,
    BAT_V2_REDEEM_ENDPOINT_V2, BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
    BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
};

/// Strict production HTTPS adapter for the storeless BAT V2 redeem client.
/// WebPKI is always required in addition to the signed leaf-SPKI pins.
#[derive(Clone, Debug)]
pub struct StrictHttpsBatV2RedeemTransportV2 {
    issuer_origin: String,
    leaf_spki_sha256_pins: Vec<[u8; 32]>,
    client: StrictHttpsClientV1,
}

impl StrictHttpsBatV2RedeemTransportV2 {
    pub fn new(
        issuer_origin: String,
        connect_timeout: Duration,
        io_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<Self, String> {
        StrictHttpsClientV1::validate_base_endpoint(&issuer_origin)?;
        let client = StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            connect_timeout,
            io_timeout,
            leaf_spki_sha256_pins,
        )?;
        Ok(Self {
            issuer_origin,
            leaf_spki_sha256_pins: leaf_spki_sha256_pins.to_vec(),
            client,
        })
    }

    #[cfg(feature = "test-only-webpki-root")]
    pub fn new_with_test_only_webpki_root_pem(
        issuer_origin: String,
        connect_timeout: Duration,
        io_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
        test_only_root_pem: &[u8],
    ) -> Result<Self, String> {
        StrictHttpsClientV1::validate_base_endpoint(&issuer_origin)?;
        let client =
            StrictHttpsClientV1::new_with_leaf_spki_sha256_pins_and_test_only_webpki_root_pem(
                connect_timeout,
                io_timeout,
                leaf_spki_sha256_pins,
                test_only_root_pem,
            )?;
        Ok(Self {
            issuer_origin,
            leaf_spki_sha256_pins: leaf_spki_sha256_pins.to_vec(),
            client,
        })
    }

    pub fn issuer_origin(&self) -> &str {
        &self.issuer_origin
    }
}

impl BatV2RedeemTransportV2 for StrictHttpsBatV2RedeemTransportV2 {
    fn redeem_v2(
        &self,
        request: BatV2RedeemHttpRequestV2<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, BatV2RedeemTransportErrorV2> {
        if request.issuer_origin != self.issuer_origin
            || request.leaf_spki_sha256_pins != self.leaf_spki_sha256_pins
            || request.endpoint != BAT_V2_REDEEM_ENDPOINT_V2
            || request.request_content_type != BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2
            || request.response_content_type != BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2
        {
            return Err(BatV2RedeemTransportErrorV2::DefinitelyNotSent { retry_after_ms: 0 });
        }
        self.client
            .post_with_error_content_type(
                &self.issuer_origin,
                BAT_V2_REDEEM_ENDPOINT_V2,
                BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
                BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
                "application/problem+json",
                request.canonical_envelope,
                max_response_bytes,
            )
            .map_err(map_bat_v2_https_error)
    }
}

fn map_bat_v2_https_error(error: HttpsPostErrorV1) -> BatV2RedeemTransportErrorV2 {
    match error {
        HttpsPostErrorV1::DefinitelyNotSent => {
            BatV2RedeemTransportErrorV2::DefinitelyNotSent { retry_after_ms: 0 }
        }
        HttpsPostErrorV1::OutcomeUnknown
        | HttpsPostErrorV1::InvalidResponse
        | HttpsPostErrorV1::HttpStatus { .. } => BatV2RedeemTransportErrorV2::OutcomeUnknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn bat_v2_https_only_definitely_not_sent_is_retry_safe() {
        assert_eq!(
            map_bat_v2_https_error(HttpsPostErrorV1::DefinitelyNotSent),
            BatV2RedeemTransportErrorV2::DefinitelyNotSent { retry_after_ms: 0 }
        );
        assert_eq!(
            map_bat_v2_https_error(HttpsPostErrorV1::OutcomeUnknown),
            BatV2RedeemTransportErrorV2::OutcomeUnknown
        );
        assert_eq!(
            map_bat_v2_https_error(HttpsPostErrorV1::InvalidResponse),
            BatV2RedeemTransportErrorV2::OutcomeUnknown
        );
        for status in 0..=u16::MAX {
            assert_eq!(
                map_bat_v2_https_error(HttpsPostErrorV1::HttpStatus {
                    status,
                    body: Zeroizing::new(Vec::new()),
                }),
                BatV2RedeemTransportErrorV2::OutcomeUnknown
            );
        }
    }

    #[test]
    fn bat_v2_https_constructor_rejects_unsafe_origin_or_pins() {
        for origin in [
            "http://issuer.example",
            "https://issuer.example/",
            "https://user@issuer.example",
            "https://issuer.example?query",
        ] {
            assert!(StrictHttpsBatV2RedeemTransportV2::new(
                origin.to_owned(),
                Duration::from_secs(1),
                Duration::from_secs(1),
                &[[1; 32]],
            )
            .is_err());
        }
        assert!(StrictHttpsBatV2RedeemTransportV2::new(
            "https://issuer.example/api".to_owned(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            &[[1; 32]],
        )
        .is_ok());
    }

    #[test]
    fn bat_v2_https_rejects_misbound_signed_transport_inputs_before_send() {
        let transport = StrictHttpsBatV2RedeemTransportV2::new(
            "https://issuer.example/api".to_owned(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            &[[1; 32]],
        )
        .unwrap();
        let assert_not_sent = |request| {
            assert_eq!(
                transport.redeem_v2(request, 339),
                Err(BatV2RedeemTransportErrorV2::DefinitelyNotSent { retry_after_ms: 0 })
            );
        };
        assert_not_sent(BatV2RedeemHttpRequestV2 {
            issuer_origin: "https://other.example/api",
            leaf_spki_sha256_pins: &[[1; 32]],
            endpoint: BAT_V2_REDEEM_ENDPOINT_V2,
            request_content_type: BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
            response_content_type: BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
            canonical_envelope: &[],
        });
        assert_not_sent(BatV2RedeemHttpRequestV2 {
            issuer_origin: "https://issuer.example/api",
            leaf_spki_sha256_pins: &[[2; 32]],
            endpoint: BAT_V2_REDEEM_ENDPOINT_V2,
            request_content_type: BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
            response_content_type: BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
            canonical_envelope: &[],
        });
        assert_not_sent(BatV2RedeemHttpRequestV2 {
            issuer_origin: "https://issuer.example/api",
            leaf_spki_sha256_pins: &[[1; 32]],
            endpoint: "/v2/redeems/",
            request_content_type: BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
            response_content_type: BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
            canonical_envelope: &[],
        });
        assert_not_sent(BatV2RedeemHttpRequestV2 {
            issuer_origin: "https://issuer.example/api",
            leaf_spki_sha256_pins: &[[1; 32]],
            endpoint: BAT_V2_REDEEM_ENDPOINT_V2,
            request_content_type: "application/octet-stream",
            response_content_type: BAT_V2_REDEEM_RESPONSE_CONTENT_TYPE_V2,
            canonical_envelope: &[],
        });
        assert_not_sent(BatV2RedeemHttpRequestV2 {
            issuer_origin: "https://issuer.example/api",
            leaf_spki_sha256_pins: &[[1; 32]],
            endpoint: BAT_V2_REDEEM_ENDPOINT_V2,
            request_content_type: BAT_V2_REDEEM_REQUEST_CONTENT_TYPE_V2,
            response_content_type: "application/octet-stream",
            canonical_envelope: &[],
        });
    }
}
