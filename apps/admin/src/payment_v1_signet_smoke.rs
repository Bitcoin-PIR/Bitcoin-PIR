//! Explicit, one-shot Signet Payment V1 functional smoke.
//!
//! This command deliberately couples no query data to a payment.  It verifies
//! a provider before requesting an invoice, asks a separately configured
//! Signet payer CLN to pay the verified invoice, claims one provider-bound
//! capability, and proves that the provider admits it.  It never sends a PIR
//! frame after admission.

use clap::{Args, ValueEnum};
use ed25519_dalek::VerifyingKey;
use pir_arc_adapter::{
    create_arc_credential_request, ArcClientStateStoreV1, ArcIssuanceCanonicalizerV1,
};
use pir_payment_crypto::{
    blind_cashu_message_v1, sign_bip340_prehash_v1, verify_and_unblind_cashu_promise_v1,
};
use pir_sdk_client::attest::{attest, SevStatus};
use pir_sdk_client::channel::{establish, SecureChannelTransport};
use pir_sdk_client::service::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    AcceptedServicePolicyV1, ServicePolicyCheckpointV1,
};
use pir_sdk_client::{Bolt11QuoteKeyCheckpointV1, WsConnection};
use pir_service_protocol::{
    AcquisitionMethod, AuthScheme, BackendId, BitcoinPirCashuBatIssuanceRequestItemV1,
    BitcoinPirCashuBatProofV1, Bolt11QuoteKeyDelegationV1, Bolt11QuoteStatusV1,
    CheckedCredentialIssuanceResponseV1, CredentialIssuanceRequestItemsV1,
    CredentialKeyBindingExpectationV1, DeploymentStatus, FreeModeV1, LightningNetworkV1,
    OperationStartV1, WorkloadId,
};
use pir_strict_https::StrictHttpsClientV1;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use zeroize::{Zeroize, Zeroizing};

const CT_QUOTE_INTENT: &str = "application/vnd.bitcoinpir.bolt11-quote-intent-v1";
const CT_QUOTE: &str = "application/vnd.bitcoinpir.bolt11-quote-v1";
const CT_STATUS_REQUEST: &str = "application/vnd.bitcoinpir.bolt11-quote-status-request-v1";
const CT_CLAIM_ENVELOPE: &str = "application/vnd.bitcoinpir.bolt11-quote-claim-envelope-v1";
const CT_ISSUANCE_RESPONSE: &str = "application/vnd.bitcoinpir.credential-issuance-response-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum PaidMethodV1 {
    DirectReceipt,
    CashuBat,
    ArcExperimental,
}

impl PaidMethodV1 {
    const fn scheme(self) -> AuthScheme {
        match self {
            Self::DirectReceipt => AuthScheme::Bolt11DirectReceiptV1,
            Self::CashuBat => AuthScheme::BitcoinPirCashuBatV1,
            Self::ArcExperimental => AuthScheme::ArcV1Experimental,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::DirectReceipt => "direct-receipt",
            Self::CashuBat => "cashu-bat",
            Self::ArcExperimental => "arc-experimental",
        }
    }
}

#[derive(Args, Debug)]
pub struct PaymentV1SignetSmokeArgs {
    /// Provider WebSocket URL. The command attests and upgrades this channel
    /// before it asks the issuer to create an invoice.
    #[arg(long)]
    pub server_url: String,
    /// Pinned lowercase provider ID from the operator's deployment artifact.
    #[arg(long)]
    pub provider_id_hex: String,
    /// Pinned lowercase service-policy Ed25519 public key.
    #[arg(long)]
    pub policy_signing_key_hex: String,
    /// Canonical HTTPS issuer origin. It must equal the selected signed offer.
    #[arg(long)]
    pub issuer_url: String,
    /// Canonical quote-key delegation bytes previously fetched from the
    /// issuer's public endpoint. This is public material, not a credential.
    #[arg(long)]
    pub quote_delegation_file: PathBuf,
    /// Fresh owner-only path for the advanced quote-key checkpoint. It is
    /// created before quote creation and removed on complete success.
    #[arg(long)]
    pub quote_checkpoint_file: PathBuf,
    /// Independently pinned Signet payee node public key (66 lowercase hex).
    #[arg(long)]
    pub expected_signet_payee_hex: String,
    /// Absolute path to the isolated Signet payer's lightning-cli.
    #[arg(long)]
    pub payer_lightning_cli: PathBuf,
    /// Isolated Signet payer lightning directory passed to lightning-cli.
    #[arg(long)]
    pub payer_lightning_dir: PathBuf,
    /// BOLT11 capability family to purchase and present.
    #[arg(long, value_enum)]
    pub method: PaidMethodV1,
    /// Required acknowledgement before this command can ask the payer CLN to
    /// make a Signet payment. Mainnet is never selected by this command.
    #[arg(long)]
    pub acknowledge_signet_test_payment: bool,
    /// DPF database ID bound into the admission-only operation.
    #[arg(long, default_value_t = 0)]
    pub dpf_db_id: u8,
    /// Bounded wait for the issuer to observe settlement after payer CLN has
    /// returned success.
    #[arg(long, default_value_t = 60)]
    pub settlement_timeout_seconds: u64,
    /// Fresh owner-only ARC initial-state file. Required for experimental ARC
    /// because the successor nonce state must commit before presentation.
    #[arg(long)]
    pub arc_initial_state_file: Option<PathBuf>,
    /// Fresh owner-only ARC successor-state file. Required with
    /// --arc-initial-state-file and removed on complete success.
    #[arg(long)]
    pub arc_successor_state_file: Option<PathBuf>,
}

pub async fn run(args: PaymentV1SignetSmokeArgs) -> Result<(), String> {
    if !args.acknowledge_signet_test_payment {
        return Err(
            "refusing to invoke a Lightning payer without --acknowledge-signet-test-payment"
                .to_owned(),
        );
    }
    if args.settlement_timeout_seconds == 0 || args.settlement_timeout_seconds > 300 {
        return Err("--settlement-timeout-seconds must be in 1..=300".to_owned());
    }
    let arc_paths = match args.method {
        PaidMethodV1::ArcExperimental => Some(require_arc_paths(&args)?),
        _ if args.arc_initial_state_file.is_some() || args.arc_successor_state_file.is_some() => {
            return Err("ARC state paths are valid only with --method arc-experimental".to_owned())
        }
        _ => None,
    };

    let provider_id = decode_hex_32(&args.provider_id_hex, "--provider-id-hex")?;
    let policy_key = VerifyingKey::from_bytes(&decode_hex_32(
        &args.policy_signing_key_hex,
        "--policy-signing-key-hex",
    )?)
    .map_err(|_| "--policy-signing-key-hex is not an Ed25519 public key".to_owned())?;
    let expected_payee = decode_hex_33(
        &args.expected_signet_payee_hex,
        "--expected-signet-payee-hex",
    )?;
    let delegation_bytes = std::fs::read(&args.quote_delegation_file)
        .map_err(|_| "could not read quote-key delegation file".to_owned())?;
    let delegation = Bolt11QuoteKeyDelegationV1::decode(&delegation_bytes)
        .map_err(|_| "quote-key delegation is invalid".to_owned())?;
    if delegation.network != LightningNetworkV1::Signet
        || delegation.expected_payee_pubkey != expected_payee
    {
        return Err("quote-key delegation does not match the pinned Signet payee".to_owned());
    }

    // This first verified secure channel is intentionally before invoice I/O.
    let (secure, accepted) =
        open_verified_provider(&args.server_url, provider_id, &policy_key).await?;
    let (scope_id, offer) = select_dpf_offer(&accepted, args.method)?;
    if offer.endpoint != args.issuer_url {
        return Err("--issuer-url differs from the exact signed offer endpoint".to_owned());
    }
    if args.method != PaidMethodV1::CashuBat && offer.credential_count != 1 {
        return Err(
            "direct-receipt and ARC admission-only smoke require a signed credential_count of exactly one"
                .to_owned(),
        );
    }
    if args.method == PaidMethodV1::ArcExperimental
        && offer.deployment_status != DeploymentStatus::Experimental
    {
        return Err("ARC offer is not explicitly marked experimental".to_owned());
    }

    let now_unix = trusted_now_unix()?;
    let checkpoint = Bolt11QuoteKeyCheckpointV1::initial(
        delegation.issuer_id,
        delegation.network,
        delegation.expected_payee_pubkey,
    )
    .map_err(|error| format!("could not initialize quote checkpoint: {error}"))?;
    let claim_secret = Zeroizing::new(fresh_claim_secret()?);
    let (claim_pubkey, _) = sign_bip340_prehash_v1(&claim_secret, &[7; 32], &[0; 32])
        .map_err(|_| "could not derive BIP340 claim public key".to_owned())?;
    let prepared = accepted
        .dangerous_unpaired_prepare_bolt11_quote_v1(
            &scope_id,
            offer.offer_id,
            &delegation_bytes,
            &checkpoint,
            now_unix,
            claim_pubkey,
            random_nonzero_32()?,
        )
        .map_err(|error| format!("could not prepare verified BOLT11 quote: {error}"))?;
    pir_private_files::write_new_private_file_v1(
        &args.quote_checkpoint_file,
        &prepared.quote_key_checkpoint_bytes(),
        "BOLT11 quote checkpoint",
    )?;

    let intent = prepared
        .intent_bytes()
        .map_err(|error| format!("could not encode quote intent: {error}"))?;
    let quote_bytes = strict_post(
        "quote",
        &args.issuer_url,
        "/v1/quotes/bolt11",
        CT_QUOTE_INTENT,
        CT_QUOTE,
        intent,
    )
    .await?;
    let mut quote = prepared
        .accept_initial_quote_for_payment(&quote_bytes, trusted_now_unix()?)
        .map_err(|error| format!("issuer quote verification failed: {error}"))?;
    if quote.status() != Bolt11QuoteStatusV1::InvoiceOpen {
        return Err("fresh BOLT11 quote was not payable".to_owned());
    }

    pay_verified_signet_invoice(&args, quote.invoice()).await?;
    // The issuer also guards invoice-creation-to-status progression at second
    // granularity. Do not send the first authenticated status request in the
    // same second in which the payer settled the invoice.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    quote = poll_until_settled(&args, &prepared, quote, &claim_secret).await?;
    // The issuer guards settlement-to-claim lifecycle progression at second
    // granularity. Do not issue the authenticated claim in the same second in
    // which the settled status was accepted.
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let binding = offer
        .credential_binding
        .clone()
        .ok_or_else(|| "selected BOLT11 offer has no credential binding".to_owned())?;
    let issuer_time = quote.invoice_created_at();
    let (items, bat_secrets, arc_pending) = build_issuance_items(
        args.method,
        &binding,
        &accepted,
        &scope_id,
        &offer,
        issuer_time,
    )?;
    let claim = prepared
        .prepare_claim(
            &quote,
            items,
            &claim_secret,
            random_nonzero_32()?,
            trusted_now_unix()?,
        )
        .map_err(|error| format!("could not prepare quote claim: {error}"))?;
    let claim_route = format!("/v1/quotes/{}/claim", hex::encode(quote.quote_id()));
    let issuance = strict_post(
        "claim",
        &args.issuer_url,
        &claim_route,
        CT_CLAIM_ENVELOPE,
        CT_ISSUANCE_RESPONSE,
        claim.envelope_bytes().to_vec(),
    )
    .await?;
    let arc_codec = ArcIssuanceCanonicalizerV1;
    let checked = prepared
        .verify_issuance_response(
            &quote,
            &claim,
            &issuance,
            (args.method == PaidMethodV1::ArcExperimental)
                .then_some(&arc_codec as &dyn pir_service_protocol::ArcIssuanceCanonicalizerV1),
            trusted_now_unix()?,
        )
        .map_err(|error| format!("issuer capability verification failed: {error}"))?;

    let proof_bytes = match (args.method, checked) {
        (
            PaidMethodV1::DirectReceipt,
            CheckedCredentialIssuanceResponseV1::DirectPaidReceipts(mut receipts),
        ) => {
            let receipt = receipts
                .pop()
                .ok_or_else(|| "issuer returned no direct receipt".to_owned())?;
            Zeroizing::new(
                receipt
                    .encode()
                    .map_err(|error| format!("could not encode direct receipt: {error}"))?,
            )
        }
        (
            PaidMethodV1::CashuBat,
            CheckedCredentialIssuanceResponseV1::BitcoinPirCashuBat { unverified_dleq },
        ) => {
            let secrets =
                bat_secrets.ok_or_else(|| "internal BAT secrets were unavailable".to_owned())?;
            if unverified_dleq.len() != secrets.len() {
                return Err(
                    "issuer returned a Cashu BAT count different from the signed offer".to_owned(),
                );
            }
            // Every signed BAT entitlement is DLEQ-verified before any one is
            // presented. The admission-only smoke retains no spare proof: the
            // unpresented, verified capabilities are dropped and zeroized at
            // the end of this branch, deliberately burning those entitlements.
            let mut proofs = Vec::with_capacity(secrets.len());
            for (secret, tuple) in secrets.into_iter().zip(unverified_dleq) {
                let verified = verify_and_unblind_cashu_promise_v1(
                    &secret.secret[..],
                    &secret.blinding_scalar,
                    &tuple.issuer_public_key,
                    &tuple.blinded_message,
                    &tuple.blinded_signature,
                    &tuple.dleq_e,
                    &tuple.dleq_s,
                )
                .map_err(|_| "issuer BAT response failed DLEQ/unblind verification".to_owned())?;
                let proof = BitcoinPirCashuBatProofV1 {
                    secret_raw: *secret.secret,
                    c: *verified.unblinded_signature(),
                };
                proofs.push(Zeroizing::new(
                    proof
                        .encode_zeroizing()
                        .map_err(|error| format!("could not encode Cashu BAT: {error}"))?
                        .to_vec(),
                ));
            }
            proofs
                .pop()
                .ok_or_else(|| "issuer returned no Cashu BAT".to_owned())?
        }
        (
            PaidMethodV1::ArcExperimental,
            CheckedCredentialIssuanceResponseV1::ArcExperimental {
                mut pending_finalize,
            },
        ) => {
            let pending = arc_pending
                .ok_or_else(|| "internal ARC pending request was unavailable".to_owned())?;
            let pair = pending_finalize
                .pop()
                .ok_or_else(|| "issuer returned no ARC credential".to_owned())?;
            let expected = binding_expectation(&accepted, &scope_id, &offer, &binding);
            let credential = pending
                .finalize(&binding, &expected, issuer_time, &pair)
                .map_err(|_| "issuer ARC response could not be finalized".to_owned())?;
            let (initial_path, successor_path) = arc_paths.as_ref().expect("ARC paths checked");
            let mut store = ArcScratchStore::new(initial_path.clone(), successor_path.clone());
            let persisted = credential
                .persist_initial(&mut store)
                .map_err(|_| "could not durably persist ARC initial state".to_owned())?;
            let waiting = persisted
                .prepare_presentation(&mut rand_core::OsRng)
                .map_err(|_| "could not prepare ARC presentation".to_owned())?;
            let (_successor, ready) = waiting
                .persist_successor(&mut store)
                .map_err(|_| "could not durably persist ARC successor state".to_owned())?;
            // The authorization helper owns the outer `ArcPresentationV1`
            // envelope. Supply only ARC's canonical inner presentation here;
            // encoding it first would double-wrap the wire payload.
            Zeroizing::new(ready.into_presentation().presentation_bytes().to_vec())
        }
        _ => return Err("issuer response did not match the selected BOLT11 method".to_owned()),
    };

    // Reconnect after payment/HTTP I/O. The accepted policy is channel-bound,
    // so the second secure channel receives a fresh authenticated snapshot.
    drop(secure);
    let (mut gate_channel, gate_policy) =
        open_verified_provider(&args.server_url, provider_id, &policy_key).await?;
    if gate_policy.policy_digest() != accepted.policy_digest() {
        return Err(
            "provider policy changed after payment; retained-policy smoke is not automatic"
                .to_owned(),
        );
    }
    let proof = dangerous_unpaired_build_authorization_proof_v1(
        &gate_policy,
        &scope_id,
        offer.offer_id,
        &proof_bytes,
    )
    .map_err(|error| format!("issued capability did not match the provider offer: {error}"))?;
    let grant = dangerous_unpaired_authorize_service_operation_v1(
        &mut gate_channel,
        &gate_policy,
        scope_id,
        offer.offer_id,
        OperationStartV1::DpfQuery {
            db_id: args.dpf_db_id,
        },
        proof,
    )
    .await
    .map_err(|error| {
        format!("provider rejected paid capability or outcome is ambiguous: {error}")
    })?;

    remove_private_file(&args.quote_checkpoint_file, "BOLT11 quote checkpoint")?;
    if let Some((initial, successor)) = arc_paths {
        remove_private_file(&initial, "ARC initial state")?;
        remove_private_file(&successor, "ARC successor state")?;
    }
    println!(
        "Payment V1 Signet smoke: {} admission granted (enforced_profile={}, expires_in_ms={}); no PIR query was sent",
        args.method.label(),
        grant.enforced_profile,
        grant.expires_in_ms
    );
    Ok(())
}

struct BatSecretV1 {
    secret: Zeroizing<[u8; 32]>,
    blinding_scalar: Zeroizing<[u8; 32]>,
}

type IssuanceItemsV1 = (
    CredentialIssuanceRequestItemsV1,
    Option<Vec<BatSecretV1>>,
    Option<pir_arc_adapter::PendingArcCredentialRequestV1>,
);

fn build_issuance_items(
    method: PaidMethodV1,
    binding: &pir_service_protocol::CredentialKeyBindingV1,
    accepted: &AcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer: &pir_service_protocol::ServiceOfferV1,
    now_unix: u64,
) -> Result<IssuanceItemsV1, String> {
    match method {
        PaidMethodV1::DirectReceipt => Ok((
            CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
            None,
            None,
        )),
        PaidMethodV1::CashuBat => {
            let count = usize::try_from(offer.credential_count).map_err(|_| {
                "signed Cashu BAT credential_count does not fit this client".to_owned()
            })?;
            let mut secrets = Vec::with_capacity(count);
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let secret = Zeroizing::new(random_nonzero_32()?);
                let blinding_scalar = Zeroizing::new(fresh_cashu_scalar()?);
                let blinded = blind_cashu_message_v1(&secret[..], &blinding_scalar)
                    .map_err(|_| "could not blind fresh Cashu BAT request".to_owned())?;
                items.push(BitcoinPirCashuBatIssuanceRequestItemV1 {
                    blinded_message: blinded,
                });
                secrets.push(BatSecretV1 {
                    secret,
                    blinding_scalar,
                });
            }
            Ok((
                CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items),
                Some(secrets),
                None,
            ))
        }
        PaidMethodV1::ArcExperimental => {
            let expected = binding_expectation(accepted, scope_id, offer, binding);
            let (request, pending) =
                create_arc_credential_request(binding, &expected, now_unix, &mut rand_core::OsRng)
                    .map_err(|_| "could not create ARC credential request".to_owned())?;
            Ok((
                CredentialIssuanceRequestItemsV1::ArcExperimental(vec![request]),
                None,
                Some(pending),
            ))
        }
    }
}

fn binding_expectation<'a>(
    accepted: &'a AcceptedServicePolicyV1,
    scope_id: &'a [u8; 32],
    offer: &'a pir_service_protocol::ServiceOfferV1,
    binding: &'a pir_service_protocol::CredentialKeyBindingV1,
) -> CredentialKeyBindingExpectationV1<'a> {
    CredentialKeyBindingExpectationV1 {
        issuer_id: &offer.issuer_id,
        provider_id: &accepted.policy().provider_id,
        scope_id,
        offer_id: offer.offer_id,
        scheme: offer.authorization,
        minimum_keyset_epoch: binding.claims.keyset_epoch,
        entitlement_profile: binding.claims.entitlement_profile,
        presentation_limit: offer.credential_presentation_limit,
        credential_key_id: &offer.key_id,
    }
}

fn select_dpf_offer(
    accepted: &AcceptedServicePolicyV1,
    method: PaidMethodV1,
) -> Result<([u8; 32], pir_service_protocol::ServiceOfferV1), String> {
    let scope = accepted
        .policy()
        .scopes
        .iter()
        .find(|scope| {
            scope.scope.backend == BackendId::DpfPirV1
                && scope.scope.workload == WorkloadId::DpfEvaluateJobV1
        })
        .ok_or_else(|| "signed provider policy has no DPF query scope".to_owned())?;
    let offer = scope
        .offers
        .iter()
        .find(|offer| {
            offer.acquisition == AcquisitionMethod::Bolt11V1
                && offer.authorization == method.scheme()
                && offer.free_mode == FreeModeV1::NotFree
        })
        .cloned()
        .ok_or_else(|| "signed provider policy has no requested DPF BOLT11 offer".to_owned())?;
    Ok((scope.scope.scope_id(), offer))
}

async fn open_verified_provider(
    server_url: &str,
    provider_id: [u8; 32],
    policy_key: &VerifyingKey,
) -> Result<
    (
        SecureChannelTransport<WsConnection>,
        AcceptedServicePolicyV1,
    ),
    String,
> {
    let mut conn = WsConnection::connect(server_url)
        .await
        .map_err(|error| format!("provider connect failed: {error}"))?;
    let nonce = random_nonzero_32()?;
    let attestation = attest(&mut conn, nonce)
        .await
        .map_err(|error| format!("provider attestation failed: {error}"))?;
    if !matches!(
        attestation.sev_status,
        SevStatus::ReportDataMatch | SevStatus::NoSevHost
    ) {
        return Err("provider attestation channel binding failed".to_owned());
    }
    if attestation.response.server_static_pub == [0; 32] {
        return Err("provider has no secure-channel static key".to_owned());
    }
    let mut secure = establish(
        conn,
        attestation.response.server_static_pub,
        random_nonzero_32()?,
        random_nonzero_32()?,
    )
    .await
    .map_err(|error| format!("provider secure-channel upgrade failed: {error}"))?;
    let accepted = fetch_verified_service_policy_v1(
        &mut secure,
        provider_id,
        policy_key,
        trusted_now_unix()?,
        &ServicePolicyCheckpointV1::initial(),
    )
    .await
    .map_err(|error| format!("provider service-policy verification failed: {error}"))?;
    Ok((secure, accepted))
}

async fn pay_verified_signet_invoice(
    args: &PaymentV1SignetSmokeArgs,
    invoice: &str,
) -> Result<(), String> {
    let mut command = Command::new(&args.payer_lightning_cli);
    command
        .arg(format!(
            "--lightning-dir={}",
            args.payer_lightning_dir.display()
        ))
        .arg("--network=signet")
        .arg("pay")
        .arg(invoice);
    let mut output = command
        .output()
        .await
        .map_err(|_| "could not execute isolated Signet payer lightning-cli".to_owned())?;
    let success = output.status.success();
    output.stdout.zeroize();
    output.stderr.zeroize();
    if !success {
        return Err("isolated Signet payer rejected the verified invoice".to_owned());
    }
    Ok(())
}

async fn poll_until_settled(
    args: &PaymentV1SignetSmokeArgs,
    prepared: &pir_sdk_client::PreparedBolt11QuoteV1,
    mut quote: pir_sdk_client::AcceptedBolt11QuoteV1,
    claim_secret: &[u8; 32],
) -> Result<pir_sdk_client::AcceptedBolt11QuoteV1, String> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(args.settlement_timeout_seconds);
    loop {
        let status = prepared
            .build_status_request(
                &quote,
                claim_secret,
                trusted_now_unix()?,
                random_nonzero_32()?,
                random_nonzero_32()?,
            )
            .map_err(|error| {
                format!("could not build authenticated quote status request: {error}")
            })?;
        let route = format!("/v1/quotes/{}/status", hex::encode(quote.quote_id()));
        let latest = strict_post(
            "status",
            &args.issuer_url,
            &route,
            CT_STATUS_REQUEST,
            CT_QUOTE,
            status,
        )
        .await?;
        quote = quote
            .accept_latest_after(prepared, &latest, trusted_now_unix()?)
            .map_err(|error| format!("issuer status verification failed: {error}"))?;
        match quote.status() {
            Bolt11QuoteStatusV1::PaymentSettled => return Ok(quote),
            Bolt11QuoteStatusV1::InvoiceOpen => {}
            Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile => {
                return Err(
                    "paid Signet invoice expired before issuer settlement observation".to_owned(),
                )
            }
            Bolt11QuoteStatusV1::LateSettledReconcile | Bolt11QuoteStatusV1::CredentialClaimed => {
                return Err(
                    "issuer returned an unexpected quote lifecycle state for a fresh smoke"
                        .to_owned(),
                )
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "issuer did not observe Signet settlement before the configured timeout".to_owned(),
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn strict_post(
    stage: &'static str,
    issuer_url: &str,
    route: &str,
    request_content_type: &str,
    response_content_type: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let issuer_url = issuer_url.to_owned();
    let route = route.to_owned();
    let request_content_type = request_content_type.to_owned();
    let response_content_type = response_content_type.to_owned();
    tokio::task::spawn_blocking(move || {
        let client = StrictHttpsClientV1::new(Duration::from_secs(10), Duration::from_secs(10))
            .map_err(|_| format!("{stage}: could not initialize strict HTTPS client"))?;
        client
            .post_with_error_content_type(
                &issuer_url,
                &route,
                &request_content_type,
                &response_content_type,
                "application/problem+json",
                &body,
                128 * 1024,
            )
            .map_err(|error| format!("{stage}: issuer HTTPS request failed: {error:?}"))
    })
    .await
    .map_err(|_| format!("{stage}: issuer HTTPS worker failed"))?
}

struct ArcScratchStore {
    initial_path: PathBuf,
    successor_path: PathBuf,
    credential_id: Option<[u8; 32]>,
    current_digest: Option<[u8; 32]>,
}

impl ArcScratchStore {
    fn new(initial_path: PathBuf, successor_path: PathBuf) -> Self {
        Self {
            initial_path,
            successor_path,
            credential_id: None,
            current_digest: None,
        }
    }
}

impl ArcClientStateStoreV1 for ArcScratchStore {
    type Error = String;

    fn persist_initial(
        &mut self,
        credential_id: &[u8; 32],
        state_digest: &[u8; 32],
        encoded_state: &[u8],
    ) -> Result<(), Self::Error> {
        if self.credential_id.is_some() {
            return Err("ARC initial state was already persisted".to_owned());
        }
        pir_private_files::write_new_private_file_v1(
            &self.initial_path,
            encoded_state,
            "ARC initial state",
        )?;
        self.credential_id = Some(*credential_id);
        self.current_digest = Some(*state_digest);
        Ok(())
    }

    fn compare_and_swap_successor(
        &mut self,
        credential_id: &[u8; 32],
        expected_state_digest: &[u8; 32],
        successor_state_digest: &[u8; 32],
        encoded_successor_state: &[u8],
    ) -> Result<(), Self::Error> {
        if self.credential_id != Some(*credential_id)
            || self.current_digest != Some(*expected_state_digest)
        {
            return Err(
                "ARC state predecessor does not match the durable scratch state".to_owned(),
            );
        }
        pir_private_files::write_new_private_file_v1(
            &self.successor_path,
            encoded_successor_state,
            "ARC successor state",
        )?;
        self.current_digest = Some(*successor_state_digest);
        Ok(())
    }

    fn load_current(
        &mut self,
        _credential_id: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Err(
            "ARC scratch store does not support recovery; preserve its owner-only files on failure"
                .to_owned(),
        )
    }
}

fn require_arc_paths(args: &PaymentV1SignetSmokeArgs) -> Result<(PathBuf, PathBuf), String> {
    let initial = args
        .arc_initial_state_file
        .clone()
        .ok_or_else(|| "--method arc-experimental requires --arc-initial-state-file".to_owned())?;
    let successor = args.arc_successor_state_file.clone().ok_or_else(|| {
        "--method arc-experimental requires --arc-successor-state-file".to_owned()
    })?;
    if initial == successor {
        return Err("ARC initial and successor state paths must differ".to_owned());
    }
    Ok((initial, successor))
}

fn remove_private_file(path: &Path, label: &str) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|_| format!("could not remove {label} after success"))
}

fn decode_hex_32(value: &str, flag: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{flag} must be 64 lowercase hex chars"))?;
    if bytes.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{flag} must be 64 lowercase hex chars"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{flag} must be 64 lowercase hex chars"))
}

fn decode_hex_33(value: &str, flag: &str) -> Result<[u8; 33], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{flag} must be 66 lowercase hex chars"))?;
    if bytes.len() != 33
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{flag} must be 66 lowercase hex chars"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{flag} must be 66 lowercase hex chars"))
}

fn trusted_now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
        .filter(|value| *value != 0)
        .ok_or_else(|| "trusted wall clock is unavailable".to_owned())
}

fn random_nonzero_32() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let mut value = [0u8; 32];
        getrandom::getrandom(&mut value).map_err(|_| "OS RNG failed".to_owned())?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err("could not generate a non-zero random value".to_owned())
}

fn fresh_claim_secret() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let secret = random_nonzero_32()?;
        if sign_bip340_prehash_v1(&secret, &[7; 32], &[0; 32]).is_ok() {
            return Ok(secret);
        }
    }
    Err("could not generate a canonical BIP340 claim secret".to_owned())
}

fn fresh_cashu_scalar() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let candidate = random_nonzero_32()?;
        if blind_cashu_message_v1(&[1; 32], &candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err("could not generate a canonical Cashu blinding scalar".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_32, decode_hex_33, PaidMethodV1};

    #[test]
    fn method_maps_to_exact_paid_scheme() {
        assert_eq!(
            PaidMethodV1::DirectReceipt.scheme(),
            pir_service_protocol::AuthScheme::Bolt11DirectReceiptV1
        );
        assert_eq!(
            PaidMethodV1::CashuBat.scheme(),
            pir_service_protocol::AuthScheme::BitcoinPirCashuBatV1
        );
    }

    #[test]
    fn pinned_values_require_lowercase_fixed_width_hex() {
        assert!(decode_hex_32(&"0a".repeat(32), "--value").is_ok());
        assert!(decode_hex_32(&"0A".repeat(32), "--value").is_err());
        assert!(decode_hex_33(&format!("02{}", "0a".repeat(32)), "--value").is_ok());
    }
}
