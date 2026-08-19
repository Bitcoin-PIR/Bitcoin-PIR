//! Deterministic, bounded adversarial regression corpus for the public V1
//! canonical decoders.
//!
//! This is deliberately a normal `cargo test`, not a replacement for a
//! coverage-guided fuzzer. It keeps malformed length prefixes, truncations,
//! boundary sizes, and high-entropy inputs on every offline CI run without
//! requiring `cargo-fuzz` or a network-installed toolchain.

use std::collections::BTreeSet;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use pir_service_protocol::*;

type DecoderV1 = fn(&[u8]) -> bool;

struct RejectingArcIssuanceCanonicalizer;

impl ArcIssuanceCanonicalizerV1 for RejectingArcIssuanceCanonicalizer {
    fn decode_and_reencode_request(
        &self,
        _request: &[u8],
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        Err(ServiceProtocolError::InvalidValue {
            field: "adversarial ARC request",
            reason: "no ARC parser is installed in this pure-protocol test",
        })
    }

    fn decode_and_reencode_response(
        &self,
        _response: &[u8],
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        Err(ServiceProtocolError::InvalidValue {
            field: "adversarial ARC response",
            reason: "no ARC parser is installed in this pure-protocol test",
        })
    }
}

fn reject_arc_presentation(_bytes: &[u8]) -> Result<Vec<u8>, ServiceProtocolError> {
    Err(ServiceProtocolError::InvalidValue {
        field: "adversarial ARC presentation",
        reason: "no ARC parser is installed in this pure-protocol test",
    })
}

fn public_v1_decoders() -> Vec<(&'static str, DecoderV1)> {
    vec![
        ("OperationStartV1", |bytes| {
            OperationStartV1::decode(bytes).is_ok()
        }),
        ("AuthBeginV1", |bytes| {
            AuthBeginV1::decode_padded(bytes).is_ok()
        }),
        ("AuthResultV1", |bytes| AuthResultV1::decode(bytes).is_ok()),
        ("ServicePolicyRequestV1", |bytes| {
            ServicePolicyRequestV1::decode(bytes).is_ok()
        }),
        ("ServicePolicyResponseV1", |bytes| {
            ServicePolicyResponseV1::decode(bytes).is_ok()
        }),
        ("HarmonyAttachV1", |bytes| {
            HarmonyAttachV1::decode_padded(bytes).is_ok()
        }),
        ("HarmonyAttachResultV1", |bytes| {
            HarmonyAttachResultV1::decode_padded(bytes).is_ok()
        }),
        ("PowChallengeRequestV1", |bytes| {
            PowChallengeRequestV1::decode_padded(bytes).is_ok()
        }),
        ("PowChallengeResponseV1", |bytes| {
            PowChallengeResponseV1::decode_padded(bytes).is_ok()
        }),
        ("CredentialKeyBindingV1", |bytes| {
            CredentialKeyBindingV1::decode(bytes).is_ok()
        }),
        ("BatAcceptanceClassV2", |bytes| {
            BatAcceptanceClassV2::decode(bytes).is_ok()
        }),
        ("CashuKeysetBindingV1", |bytes| {
            CashuKeysetBindingV1::decode(bytes).is_ok()
        }),
        ("StandardCashuMintManifestV1", |bytes| {
            StandardCashuMintManifestV1::decode(bytes).is_ok()
        }),
        ("FreePowProofV1", |bytes| {
            FreePowProofV1::decode(bytes).is_ok()
        }),
        ("FreeAnonymousTicketV1", |bytes| {
            FreeAnonymousTicketV1::decode(bytes).is_ok()
        }),
        ("StandardCashuSpendV1", |bytes| {
            StandardCashuSpendV1::decode(bytes).is_ok()
        }),
        ("BitcoinPirCashuBatProofV1", |bytes| {
            BitcoinPirCashuBatProofV1::decode(bytes).is_ok()
        }),
        ("ArcPresentationV1", |bytes| {
            ArcPresentationV1::decode_canonical(bytes, &reject_arc_presentation).is_ok()
        }),
        ("PaidReceiptV1", |bytes| {
            PaidReceiptV1::decode(bytes).is_ok()
        }),
        ("ServiceScopeV1", |bytes| {
            ServiceScopeV1::decode(bytes).is_ok()
        }),
        ("ServicePolicyV1", |bytes| {
            ServicePolicyV1::decode(bytes).is_ok()
        }),
        ("DirectoryOperatorAssertionV1", |bytes| {
            DirectoryOperatorAssertionV1::decode(bytes).is_ok()
        }),
        ("Bolt11QuoteKeyDelegationV1", |bytes| {
            Bolt11QuoteKeyDelegationV1::decode(bytes).is_ok()
        }),
        ("Bolt11QuoteIntentV1", |bytes| {
            Bolt11QuoteIntentV1::decode(bytes).is_ok()
        }),
        ("Bolt11QuoteV1", |bytes| {
            Bolt11QuoteV1::decode(bytes).is_ok()
        }),
        ("Bolt11QuoteStatusRequestV1", |bytes| {
            Bolt11QuoteStatusRequestV1::decode(bytes).is_ok()
        }),
        ("Bolt11QuoteClaimV1", |bytes| {
            Bolt11QuoteClaimV1::decode(bytes).is_ok()
        }),
        ("Bolt11QuoteClaimEnvelopeV1", |bytes| {
            Bolt11QuoteClaimEnvelopeV1::decode(bytes, None).is_ok()
        }),
        ("ArcCredentialRequestV1", |bytes| {
            ArcCredentialRequestV1::decode_canonical(bytes, &RejectingArcIssuanceCanonicalizer)
                .is_ok()
        }),
        ("ArcCredentialResponseV1", |bytes| {
            ArcCredentialResponseV1::decode_canonical(bytes, &RejectingArcIssuanceCanonicalizer)
                .is_ok()
        }),
        ("CredentialIssuanceRequestV1", |bytes| {
            CredentialIssuanceRequestV1::decode(bytes, None).is_ok()
        }),
        ("CredentialIssuanceResponseV1", |bytes| {
            CredentialIssuanceResponseV1::decode(bytes, None).is_ok()
        }),
        ("ProviderClearingAuthorizationV1", |bytes| {
            ProviderClearingAuthorizationV1::decode(bytes).is_ok()
        }),
        ("IssuerClearingApprovalV1", |bytes| {
            IssuerClearingApprovalV1::decode(bytes).is_ok()
        }),
        ("ProviderRedeemRequestV1", |bytes| {
            ProviderRedeemRequestV1::decode(bytes).is_ok()
        }),
        ("ProviderRedeemEnvelopeV1", |bytes| {
            ProviderRedeemEnvelopeV1::decode(bytes).is_ok()
        }),
        ("ProviderClearingRequestAuthV1", |bytes| {
            ProviderClearingRequestAuthV1::decode(bytes).is_ok()
        }),
        ("ProviderSettlementRequestAuthV1", |bytes| {
            ProviderSettlementRequestAuthV1::decode(bytes).is_ok()
        }),
        ("ProviderRedeemResponseV1", |bytes| {
            ProviderRedeemResponseV1::decode(bytes).is_ok()
        }),
        ("ProviderSettlementDepositRequestV1", |bytes| {
            ProviderSettlementDepositRequestV1::decode(bytes).is_ok()
        }),
        ("ProviderSettlementDepositResponseV1", |bytes| {
            ProviderSettlementDepositResponseV1::decode(bytes).is_ok()
        }),
        ("ProviderSettlementDepositEnvelopeV1", |bytes| {
            ProviderSettlementDepositEnvelopeV1::decode(bytes).is_ok()
        }),
        ("ProviderBalanceRequestV1", |bytes| {
            ProviderBalanceRequestV1::decode(bytes).is_ok()
        }),
        ("ProviderBalanceEnvelopeV1", |bytes| {
            ProviderBalanceEnvelopeV1::decode(bytes).is_ok()
        }),
        ("IssuerBalanceResponseV1", |bytes| {
            IssuerBalanceResponseV1::decode(bytes).is_ok()
        }),
        ("ProviderPayoutIntentRequestV1", |bytes| {
            ProviderPayoutIntentRequestV1::decode(bytes).is_ok()
        }),
        ("ProviderPayoutIntentEnvelopeV1", |bytes| {
            ProviderPayoutIntentEnvelopeV1::decode(bytes).is_ok()
        }),
        ("IssuerPayoutIntentResponseV1", |bytes| {
            IssuerPayoutIntentResponseV1::decode(bytes).is_ok()
        }),
        ("ProviderPayoutRequestV1", |bytes| {
            ProviderPayoutRequestV1::decode(bytes).is_ok()
        }),
        ("ProviderPayoutEnvelopeV1", |bytes| {
            ProviderPayoutEnvelopeV1::decode(bytes).is_ok()
        }),
        ("IssuerPayoutResponseV1", |bytes| {
            IssuerPayoutResponseV1::decode(bytes).is_ok()
        }),
        ("ProviderPayoutStatusRequestV1", |bytes| {
            ProviderPayoutStatusRequestV1::decode(bytes).is_ok()
        }),
        ("ProviderPayoutStatusEnvelopeV1", |bytes| {
            ProviderPayoutStatusEnvelopeV1::decode(bytes).is_ok()
        }),
        ("IssuerPayoutStatusResponseV1", |bytes| {
            IssuerPayoutStatusResponseV1::decode(bytes).is_ok()
        }),
    ]
}

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

fn bounded_corpus() -> Vec<Vec<u8>> {
    const LENGTHS: &[usize] = &[
        0,
        1,
        2,
        3,
        4,
        5,
        7,
        8,
        15,
        16,
        31,
        32,
        33,
        41,
        63,
        64,
        65,
        127,
        128,
        129,
        193,
        225,
        226,
        227,
        230,
        231,
        232,
        255,
        256,
        257,
        383,
        384,
        385,
        453,
        454,
        455,
        511,
        512,
        513,
        1_023,
        1_024,
        1_025,
        2_047,
        2_048,
        2_049,
        4_095,
        4_096,
        AUTH_FRAME_CLASS_V1 - 1,
        AUTH_FRAME_CLASS_V1,
        AUTH_FRAME_CLASS_V1 + 1,
    ];
    const OFFSETS: &[usize] = &[
        0, 1, 2, 3, 4, 5, 15, 16, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 159, 191, 223,
        255,
    ];
    const DECLARED_LENGTHS: &[u32] = &[0, 1, 31, 32, 255, 256, 4_096, u16::MAX as u32, u32::MAX];

    let mut corpus = Vec::new();
    for &len in LENGTHS {
        corpus.push(vec![0; len]);
        corpus.push(vec![u8::MAX; len]);
        let mut versioned = deterministic_bytes(len, 0x6a09_e667_f3bc_c909 ^ len as u64);
        if let Some(version) = versioned.first_mut() {
            *version = SERVICE_PROTOCOL_VERSION;
        }
        corpus.push(versioned);
    }

    for &offset in OFFSETS {
        for &declared in DECLARED_LENGTHS {
            let mut u16_case = deterministic_bytes(512, 0xbb67_ae85_84ca_a73b ^ offset as u64);
            u16_case[0] = SERVICE_PROTOCOL_VERSION;
            if offset + 2 <= u16_case.len() {
                u16_case[offset..offset + 2].copy_from_slice(&(declared as u16).to_le_bytes());
                corpus.push(u16_case);
            }

            let mut u32_case = deterministic_bytes(512, 0x3c6e_f372_fe94_f82b ^ offset as u64);
            u32_case[0] = SERVICE_PROTOCOL_VERSION;
            if offset + 4 <= u32_case.len() {
                u32_case[offset..offset + 4].copy_from_slice(&declared.to_le_bytes());
                corpus.push(u32_case);
            }
        }
    }
    corpus
}

fn public_decoder_source_count(path: &Path) -> usize {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .map(|entry| {
            if entry.is_dir() {
                public_decoder_source_count(&entry)
            } else if entry.extension().and_then(|value| value.to_str()) == Some("rs") {
                let source = fs::read_to_string(entry).unwrap();
                source.matches("pub fn decode(").count()
                    + source.matches("pub fn decode_padded(").count()
                    + source.matches("pub fn decode_canonical(").count()
            } else {
                0
            }
        })
        .sum()
}

#[test]
fn payment_v1_public_decoders_are_total_for_bounded_adversarial_corpus() {
    let decoders = public_v1_decoders();
    let corpus = bounded_corpus();
    let decoder_names = decoders
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        decoder_names.len(),
        decoders.len(),
        "decoder inventory labels must be unique"
    );
    assert_eq!(
        decoders.len(),
        public_decoder_source_count(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")),
        "every public V1 decoder source surface must have one adversarial harness entry"
    );
    assert_eq!(
        decoders.len(),
        54,
        "the explicit public-decoder inventory must not shrink silently"
    );
    assert!(
        corpus.len() < 1_000,
        "the CI corpus must remain explicitly bounded"
    );

    let mut accepted = 0usize;
    for (decoder_name, decoder) in decoders {
        for (case_index, bytes) in corpus.iter().enumerate() {
            let outcome = catch_unwind(AssertUnwindSafe(|| decoder(bytes)));
            let was_accepted = outcome.unwrap_or_else(|_| {
                panic!(
                    "{decoder_name} panicked on deterministic adversarial case {case_index} (len={})",
                    bytes.len()
                )
            });
            accepted += usize::from(was_accepted);
        }
    }
    assert!(
        accepted > 0,
        "the corpus must include at least one canonical input"
    );
}

#[test]
fn payment_v1_oversized_top_level_messages_fail_before_nested_decode() {
    assert!(ServicePolicyV1::decode(&vec![0; MAX_SIGNED_POLICY_LEN + 1]).is_err());
    assert!(StandardCashuSpendV1::decode(&vec![0; MAX_AUTH_PROOF_LEN + 1]).is_err());
    assert!(
        Bolt11QuoteKeyDelegationV1::decode(&vec![0; MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN + 1])
            .is_err()
    );
    assert!(Bolt11QuoteIntentV1::decode(&vec![0; MAX_BOLT11_QUOTE_INTENT_LEN + 1]).is_err());
    assert!(Bolt11QuoteV1::decode(&vec![0; MAX_BOLT11_QUOTE_LEN + 1]).is_err());
    assert!(
        Bolt11QuoteStatusRequestV1::decode(&vec![0; MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN + 1])
            .is_err()
    );
    assert!(Bolt11QuoteClaimV1::decode(&vec![0; MAX_BOLT11_QUOTE_CLAIM_LEN + 1]).is_err());
    assert!(
        ProviderRedeemEnvelopeV1::decode(&vec![0; MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1 + 1])
            .is_err()
    );
    assert!(CredentialIssuanceRequestV1::decode(
        &vec![0; MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1 + 1],
        None,
    )
    .is_err());
    assert!(CredentialIssuanceResponseV1::decode(
        &vec![0; MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1 + 1],
        None,
    )
    .is_err());
    assert!(Bolt11QuoteClaimEnvelopeV1::decode(
        &vec![0; MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1 + 1],
        None,
    )
    .is_err());
    let oversized_settlement_envelope = vec![0; MAX_SETTLEMENT_HTTP_ENVELOPE_LEN_V1 + 1];
    assert!(ProviderSettlementDepositEnvelopeV1::decode(&oversized_settlement_envelope).is_err());
    assert!(ProviderBalanceEnvelopeV1::decode(&oversized_settlement_envelope).is_err());
    assert!(ProviderPayoutIntentEnvelopeV1::decode(&oversized_settlement_envelope).is_err());
    assert!(ProviderPayoutEnvelopeV1::decode(&oversized_settlement_envelope).is_err());
    assert!(ProviderPayoutStatusEnvelopeV1::decode(&oversized_settlement_envelope).is_err());
}
