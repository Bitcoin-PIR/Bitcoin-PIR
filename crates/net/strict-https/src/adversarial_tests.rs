//! Deterministic malformed HTTP/1.1 response corpus for the strict payment
//! authority client. It can access the private parser without widening the
//! production API.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;

fn deterministic_bytes(len: usize, mut state: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push(state as u8);
    }
    bytes
}

fn bounded_http_corpus() -> Vec<Vec<u8>> {
    const LENGTHS: &[usize] = &[
        0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511,
        512, 1_023, 1_024, 1_025, 2_047, 2_048, 4_095, 4_096,
    ];
    let mut corpus = Vec::new();
    for &len in LENGTHS {
        corpus.push(vec![0; len]);
        corpus.push(vec![u8::MAX; len]);
        corpus.push(deterministic_bytes(len, 0x510e_527f_ade6_82d1 ^ len as u64));
    }

    for declared in [
        "0",
        "1",
        "1024",
        "1025",
        "18446744073709551615",
        "18446744073709551616",
        "+1",
        "-1",
        "01",
        "1 ",
    ] {
        corpus.push(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared}\r\n\r\nx"
            )
            .into_bytes(),
        );
        corpus.push(format!("{declared}\r\nx\r\n0\r\n\r\n").into_bytes());
    }
    corpus
}

#[test]
fn payment_v1_adversarial_http_boundary_is_total_and_bounded() {
    let corpus = bounded_http_corpus();
    assert!(corpus.len() < 150, "the HTTP CI corpus must remain bounded");
    for (case_index, wire) in corpus.iter().enumerate() {
        catch_unwind(AssertUnwindSafe(|| {
            let _ = parse_http_response_v1(
                wire,
                "application/octet-stream",
                "application/problem+json",
                1_024,
            );
            let _ = decode_chunked_v1(wire, 1_024);
        }))
        .unwrap_or_else(|_| {
            panic!(
                "strict HTTP parser panicked on deterministic adversarial case {case_index} (len={})",
                wire.len()
            )
        });
    }
}

#[test]
fn payment_v1_http_rejects_length_smuggling_and_unbounded_framing() {
    let malformed: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: gzip\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n1;extension=yes\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nTrailer: forbidden\r\n\r\n",
    ];
    for (case_index, wire) in malformed.iter().enumerate() {
        assert_eq!(
            parse_http_response_v1(
                wire,
                "application/octet-stream",
                "application/problem+json",
                1_024,
            ),
            Err(HttpsPostErrorV1::InvalidResponse),
            "ambiguous HTTP framing case {case_index} was accepted"
        );
    }

    let mut oversized_header =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Pad: ".to_vec();
    oversized_header.resize(MAX_HTTP_HEADER_BYTES_V1 + 1, b'a');
    oversized_header.extend_from_slice(b"\r\n\r\nx");
    assert_eq!(
        parse_http_response_v1(
            &oversized_header,
            "application/octet-stream",
            "application/problem+json",
            1_024,
        ),
        Err(HttpsPostErrorV1::InvalidResponse)
    );

    let oversized_wire = vec![0; 1_024 + MAX_HTTP_HEADER_BYTES_V1 + MAX_HTTP_WIRE_OVERHEAD_V1 + 1];
    assert_eq!(
        parse_http_response_v1(
            &oversized_wire,
            "application/octet-stream",
            "application/problem+json",
            1_024,
        ),
        Err(HttpsPostErrorV1::InvalidResponse)
    );
}

#[test]
fn payment_v1_https_endpoint_and_media_type_reject_injection_corpus() {
    for endpoint in [
        "",
        "http://issuer.example",
        "https://user@issuer.example",
        "https://issuer.example/",
        "https://issuer.example/%2e%2e",
        "https://issuer.example\r\nX-Injected: yes",
        "https://issuer.example?query=1",
        "https://issuer.example#fragment",
        "https://issuer.example:0",
        "https://issuer.example:443",
        "https://issuer.example:0443",
        "https://issuer.example:65536",
        "https://Issuer.example",
        "https://issuer.example.",
        "https://issuer..example",
        "https://-issuer.example",
        "https://issuer.example/../admin",
        "https://issuer.example/v1/./redeems",
        "https://issuer.example/v1\\redeems",
        "https://issuer.example/v1 redeems",
        "https://[0:0:0:0:0:0:0:1]",
        "https://127.000.000.001",
        "https://127.1",
        "https://2130706433",
    ] {
        assert!(HttpsEndpointV1::parse_and_join(endpoint, "/v1/redeems").is_err());
    }
    for route in [
        "",
        "v1/redeems",
        "//v1/redeems",
        "/../v1/redeems",
        "/v1/./redeems",
        "/v1/redeems?x=1",
        "/v1/redeems#fragment",
        "/v1/redeems\r\nX-Injected: yes",
    ] {
        assert!(HttpsEndpointV1::parse_and_join("https://issuer.example", route).is_err());
    }
    for media_type in [
        "",
        "application/octet-stream; charset=utf-8",
        "application/octet-stream\r\nX-Injected: yes",
        "application/octet stream",
    ] {
        assert!(!valid_media_type_v1(media_type));
    }
}

#[test]
fn payment_v1_http_requires_the_exact_status_selected_media_type() {
    let parameterized = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream; charset=binary\r\nContent-Length: 1\r\n\r\nx";
    assert_eq!(
        parse_http_response_v1(
            parameterized,
            "application/octet-stream",
            "application/problem+json",
            1_024,
        ),
        Err(HttpsPostErrorV1::InvalidResponse)
    );
    assert_eq!(
        accept_header_value_v1("application/a", "application/b"),
        "application/a, application/b"
    );
    assert_eq!(
        accept_header_value_v1("application/a", "application/a"),
        "application/a"
    );
}
