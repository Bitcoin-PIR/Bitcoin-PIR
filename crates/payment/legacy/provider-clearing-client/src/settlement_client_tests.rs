use super::*;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use pir_issuer_clearing::{
    prepare_payout_intent_response_v1, sign_and_commit_payout_execution_v1,
    sign_and_commit_payout_status_v1,
};
use pir_service_protocol::{
    verify_new_balance_request_for, verify_new_payout_intent_request_for,
    verify_new_payout_request_for, verify_new_payout_status_request_for,
    IssuerPayoutStatusResponseV1, PayoutExecutionCommitStoreV1, PayoutExecutionContextV1,
    PayoutStatusCasExpectationV1, PayoutStatusCompareAndSwapStoreV1,
    ProviderClearingAuthorizationClaimsV1, ProviderPayoutStatusEnvelopeV1, SettlementModesV1,
    SettlementRuleV1, VerifiedPayoutExecutionV1,
};

const PROVIDER_ID: [u8; 32] = [0x31; 32];
const ISSUER_ID: [u8; 32] = [0x32; 32];
const ACCOUNT_ID: [u8; 32] = [0x33; 32];
const PAYOUT_TARGET_ID: [u8; 32] = [0x34; 32];
const REGISTRATION_DIGEST: [u8; 32] = [0x35; 32];
const ROTATED_REGISTRATION_DIGEST: [u8; 32] = [0x36; 32];
const NOW: u64 = 1_500;

struct Fixture {
    operator: SigningKey,
    clearing: SigningKey,
    provider_request: SigningKey,
    issuer_settlement: SigningKey,
    rotated_issuer_settlement: SigningKey,
    authorization: ProviderClearingAuthorizationV1,
    approval: IssuerClearingApprovalV1,
    registration: ProviderSettlementRegistrationV1,
}

impl Fixture {
    fn new() -> Self {
        let operator = SigningKey::from_bytes(&[0x21; 32]);
        let clearing = SigningKey::from_bytes(&[0x22; 32]);
        let provider_request = SigningKey::from_bytes(&[0x23; 32]);
        let issuer_settlement = SigningKey::from_bytes(&[0x24; 32]);
        let rotated_issuer_settlement = SigningKey::from_bytes(&[0x25; 32]);
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [0x41; 16],
                authorization_epoch: 1,
                provider_id: PROVIDER_ID,
                issuer_id: ISSUER_ID,
                redeem_endpoint: "https://issuer.example".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[0x41; 32]],
                settlement_account_id: ACCOUNT_ID,
                clearing_verifying_key: clearing.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 2_000,
                rules: vec![SettlementRuleV1 {
                    credential_binding_digest: [0x42; 32],
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 9,
                    issuer_fee: 1,
                    denomination_profile: 1,
                    settlement_modes: SettlementModesV1::from_bits(
                        SettlementModesV1::LEDGER_CREDIT,
                    )
                    .expect("ledger-credit mode"),
                    blind_output_minimum_validity_seconds: 0,
                    blind_output_keyset: None,
                }],
            },
            &operator,
        )
        .expect("authorization");
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 1_000, 2_000, &issuer_settlement)
                .expect("approval");
        let registration = ProviderSettlementRegistrationV1 {
            registration_digest: REGISTRATION_DIGEST,
            provider_id: PROVIDER_ID,
            issuer_id: ISSUER_ID,
            settlement_account_id: ACCOUNT_ID,
            provider_request_verifying_key: provider_request.verifying_key().to_bytes(),
            payout_target_id: PAYOUT_TARGET_ID,
            not_before: 1_000,
            not_after: 2_000,
        };
        Self {
            operator,
            clearing,
            provider_request,
            issuer_settlement,
            rotated_issuer_settlement,
            authorization,
            approval,
            registration,
        }
    }

    fn trust(
        &self,
        registration: ProviderSettlementRegistrationV1,
        current: VerifyingKey,
        retained_keys: Vec<VerifyingKey>,
        retained_registrations: Vec<ProviderSettlementRegistrationV1>,
    ) -> ProviderSettlementTrustV1 {
        ProviderSettlementTrustV1 {
            authorization: self.authorization.clone(),
            issuer_approval: self.approval.clone(),
            operator_verifying_key: self.operator.verifying_key(),
            minimum_authorization_epoch: 1,
            registration,
            current_issuer_settlement_key: current,
            retained_issuer_settlement_keys: retained_keys,
            retained_registrations,
        }
    }

    fn client<'a>(
        &self,
        transport: &'a dyn ProviderSettlementTransportV1,
    ) -> ProviderSettlementClientV1<'a> {
        ProviderSettlementClientV1::new(
            self.trust(
                self.registration.clone(),
                self.issuer_settlement.verifying_key(),
                Vec::new(),
                Vec::new(),
            ),
            self.clearing.clone(),
            self.provider_request.clone(),
            transport,
        )
        .expect("provider client")
    }

    fn ledger_client<'a>(
        &self,
        current_issuer_settlement_key: VerifyingKey,
        retained_issuer_settlement_keys: Vec<VerifyingKey>,
        transport: &'a dyn ProviderSettlementTransportV1,
    ) -> ProviderLedgerBalanceClientV1<'a> {
        ProviderLedgerBalanceClientV1::new(
            ProviderLedgerBalanceTrustV1 {
                authorization: self.authorization.clone(),
                issuer_approval: self.approval.clone(),
                operator_verifying_key: self.operator.verifying_key(),
                minimum_authorization_epoch: 1,
                current_issuer_settlement_key,
                retained_issuer_settlement_keys,
            },
            self.clearing.clone(),
            transport,
        )
        .expect("provider ledger-only balance client")
    }
}

#[derive(Default)]
struct MemoryProviderStore {
    state: Option<ProviderPayoutDurableStateV1>,
    floor: Option<ProviderPayoutRollbackFloorV1>,
    history: Vec<ProviderPayoutDurableStateV1>,
    committed_pending: Option<ProviderPayoutPendingV1>,
    pending_history: Vec<ProviderPayoutPendingV1>,
    pending_payout: Option<ProviderPayoutPendingV1>,
    pending_floor: Option<ProviderPayoutPendingFloorV1>,
    pending: Option<ProviderPayoutStatusPendingV1>,
}

impl ProviderSettlementStateStoreV1 for MemoryProviderStore {
    type Error = &'static str;

    fn persist_pending_payout(
        &mut self,
        write: &VerifiedProviderPayoutPendingWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        match (&self.pending_payout, self.pending_floor) {
            (Some(existing), Some(floor)) => {
                let predecessor_matches = match pending.predecessor_floor {
                    None => self.state.is_none() && self.committed_pending.is_none(),
                    Some(predecessor) => {
                        self.state
                            .as_ref()
                            .is_some_and(|state| state.rollback_floor == predecessor)
                            && self.committed_pending.is_some()
                    }
                };
                return Ok(existing == pending
                    && floor == pending.pending_floor
                    && self.floor.is_none()
                    && predecessor_matches);
            }
            (Some(_), None) | (None, Some(_)) => return Ok(false),
            (None, None) => {}
        }
        if self.pending.is_some() {
            return Ok(false);
        }
        match pending.predecessor_floor {
            None => {
                if self.state.is_some() || self.floor.is_some() || self.committed_pending.is_some()
                {
                    return Ok(false);
                }
            }
            Some(predecessor) => {
                if !matches!(
                    predecessor.state(),
                    PayoutStateV1::Succeeded | PayoutStateV1::Failed
                ) || self.floor != Some(predecessor)
                    || self
                        .state
                        .as_ref()
                        .map_or(true, |state| state.rollback_floor != predecessor)
                {
                    return Ok(false);
                }
                let Some(committed_pending) = self.committed_pending.as_ref() else {
                    return Ok(false);
                };
                self.history.push(
                    self.state
                        .as_ref()
                        .expect("checked predecessor state")
                        .clone(),
                );
                self.pending_history.push(committed_pending.clone());
            }
        }
        self.floor = None;
        self.pending_payout = Some(pending.clone());
        self.pending_floor = Some(pending.pending_floor);
        Ok(true)
    }

    fn commit_initial_payout_from_pending(
        &mut self,
        write: &VerifiedProviderPayoutInitialWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        let state = &write.state;
        if self.pending_payout.is_none() {
            let Some(existing) = &self.state else {
                return Ok(false);
            };
            return Ok(existing == state
                && self.floor == Some(state.rollback_floor)
                && self.committed_pending.as_ref() == Some(pending)
                && self.pending_floor.is_none());
        }
        let predecessor_matches = match pending.predecessor_floor {
            None => self.state.is_none() && self.committed_pending.is_none(),
            Some(predecessor) => {
                self.state
                    .as_ref()
                    .is_some_and(|state| state.rollback_floor == predecessor)
                    && self.committed_pending.is_some()
            }
        };
        if !predecessor_matches
            || self.floor.is_some()
            || self.pending_payout.as_ref() != Some(pending)
            || self.pending_floor != Some(pending.pending_floor)
        {
            return Ok(false);
        }
        self.state = Some(state.clone());
        self.floor = Some(state.rollback_floor);
        self.committed_pending = Some(pending.clone());
        self.pending_payout = None;
        self.pending_floor = None;
        Ok(true)
    }

    fn persist_pending_status(
        &mut self,
        write: &VerifiedProviderPayoutStatusPendingWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        if self.floor != Some(pending.previous_floor) {
            return Ok(false);
        }
        if let Some(existing) = &self.pending {
            return Ok(existing == pending);
        }
        self.pending = Some(pending.clone());
        Ok(true)
    }

    fn commit_status_update(
        &mut self,
        write: &VerifiedProviderPayoutStatusWriteV1,
    ) -> Result<bool, Self::Error> {
        let pending = &write.pending;
        let state = &write.state;
        if self.pending.as_ref() != Some(pending)
            || self.floor != Some(pending.previous_floor)
            || !floor_is_satisfied(&pending.previous_floor, &state.rollback_floor)
        {
            return Ok(false);
        }
        self.state = Some(state.clone());
        self.floor = Some(state.rollback_floor);
        self.pending = None;
        Ok(true)
    }
}

#[derive(Clone, Default)]
struct SharedMemoryProviderStore(Arc<Mutex<MemoryProviderStore>>);

impl ProviderSettlementStateStoreV1 for SharedMemoryProviderStore {
    type Error = &'static str;

    fn persist_pending_payout(
        &mut self,
        write: &VerifiedProviderPayoutPendingWriteV1,
    ) -> Result<bool, Self::Error> {
        self.0
            .lock()
            .map_err(|_| "shared provider store lock poisoned")?
            .persist_pending_payout(write)
    }

    fn commit_initial_payout_from_pending(
        &mut self,
        write: &VerifiedProviderPayoutInitialWriteV1,
    ) -> Result<bool, Self::Error> {
        self.0
            .lock()
            .map_err(|_| "shared provider store lock poisoned")?
            .commit_initial_payout_from_pending(write)
    }

    fn persist_pending_status(
        &mut self,
        write: &VerifiedProviderPayoutStatusPendingWriteV1,
    ) -> Result<bool, Self::Error> {
        self.0
            .lock()
            .map_err(|_| "shared provider store lock poisoned")?
            .persist_pending_status(write)
    }

    fn commit_status_update(
        &mut self,
        write: &VerifiedProviderPayoutStatusWriteV1,
    ) -> Result<bool, Self::Error> {
        self.0
            .lock()
            .map_err(|_| "shared provider store lock poisoned")?
            .commit_status_update(write)
    }
}

fn recompute_pending_floor(pending: &mut ProviderPayoutPendingV1) {
    pending.pending_floor = pending_payout_floor_v1(
        &pending.canonical_envelope,
        &pending.payout_request_digest,
        &pending.idempotency_key,
        &pending.intent_request,
        &pending.intent_response,
        &pending.registration,
        pending.predecessor_floor.as_ref(),
    )
    .expect("bounded canonical pending payout floor");
}

struct FakeIssuer {
    authorization: ProviderClearingAuthorizationV1,
    approval: IssuerClearingApprovalV1,
    operator_key: VerifyingKey,
    provider_request_key: VerifyingKey,
    issuer_settlement: SigningKey,
    issuer_settlement_key: VerifyingKey,
    registration: ProviderSettlementRegistrationV1,
    state: Mutex<FakeIssuerState>,
}

struct FakeIssuerState {
    available_value: u64,
    reserved_value: u64,
    ledger_sequence: u64,
    next_time: u64,
    exact_responses: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    initial_payout_response: Option<IssuerPayoutResponseV1>,
    payout_request: Option<ProviderPayoutRequestV1>,
    payout_snapshot: Option<VerifiedPayoutSnapshotV1>,
    payout_posts: Vec<Vec<u8>>,
    intent_consume_count: u64,
    payout_debit_count: u64,
    outbox_insert_count: u64,
    lose_next_payout_response: bool,
    lose_next_status_response: bool,
    next_status_state: Option<PayoutStateV1>,
    corrupt_next_balance_response: bool,
}

impl FakeIssuer {
    fn new(fixture: &Fixture) -> Self {
        Self {
            authorization: fixture.authorization.clone(),
            approval: fixture.approval.clone(),
            operator_key: fixture.operator.verifying_key(),
            provider_request_key: fixture.provider_request.verifying_key(),
            issuer_settlement: fixture.issuer_settlement.clone(),
            issuer_settlement_key: fixture.issuer_settlement.verifying_key(),
            registration: fixture.registration.clone(),
            state: Mutex::new(FakeIssuerState {
                available_value: 0,
                reserved_value: 0,
                ledger_sequence: 1,
                next_time: NOW,
                exact_responses: BTreeMap::new(),
                initial_payout_response: None,
                payout_request: None,
                payout_snapshot: None,
                payout_posts: Vec::new(),
                intent_consume_count: 0,
                payout_debit_count: 0,
                outbox_insert_count: 0,
                lose_next_payout_response: false,
                lose_next_status_response: false,
                next_status_state: None,
                corrupt_next_balance_response: false,
            }),
        }
    }

    fn lose_next_payout_response(&self) {
        self.state
            .lock()
            .expect("fake issuer lock")
            .lose_next_payout_response = true;
    }

    fn lose_next_status_response(&self) {
        self.state
            .lock()
            .expect("fake issuer lock")
            .lose_next_status_response = true;
    }

    fn set_next_status_state(&self, next: PayoutStateV1) {
        self.state
            .lock()
            .expect("fake issuer lock")
            .next_status_state = Some(next);
    }

    fn commit_verified_redeem_credit(
        &self,
        accepted_value: u64,
        provider_credit: u64,
        issuer_fee: u64,
    ) {
        assert_eq!(
            provider_credit.checked_add(issuer_fee),
            Some(accepted_value)
        );
        let mut state = self.state.lock().expect("fake issuer lock");
        state.available_value = state
            .available_value
            .checked_add(provider_credit)
            .expect("bounded fake ledger credit");
        state.ledger_sequence += 1;
    }

    fn corrupt_next_balance_response(&self) {
        self.state
            .lock()
            .expect("fake issuer lock")
            .corrupt_next_balance_response = true;
    }

    fn expire_clock(&self) {
        self.state.lock().expect("fake issuer lock").next_time = 6_000;
    }

    fn payout_posts(&self) -> Vec<Vec<u8>> {
        self.state
            .lock()
            .expect("fake issuer lock")
            .payout_posts
            .clone()
    }

    fn payout_economic_counts(&self) -> (u64, u64, u64) {
        let state = self.state.lock().expect("fake issuer lock");
        (
            state.intent_consume_count,
            state.payout_debit_count,
            state.outbox_insert_count,
        )
    }

    fn expectation<'a>(&'a self, now_unix: u64) -> ProviderClearingExpectationV1<'a> {
        ProviderClearingExpectationV1 {
            provider_id: &PROVIDER_ID,
            issuer_id: &ISSUER_ID,
            operator_key: &self.operator_key,
            issuer_settlement_key: &self.issuer_settlement_key,
            now_unix,
            minimum_authorization_epoch: 1,
        }
    }

    fn generate(
        &self,
        endpoint: &str,
        body: &[u8],
        state: &mut FakeIssuerState,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        let now = state.next_time;
        state.next_time = state.next_time.saturating_add(2);
        match endpoint {
            PROVIDER_BALANCE_ENDPOINT_V1 => {
                let envelope = ProviderBalanceEnvelopeV1::decode(body)?;
                verify_new_balance_request_for(
                    &envelope.request,
                    &self.authorization,
                    &self.approval,
                    &envelope.request_auth,
                    &self.expectation(now),
                )?;
                let mut response = IssuerBalanceResponseV1::sign(
                    IssuerBalanceResponseV1 {
                        issuer_settlement_key_id: [0; 16],
                        request_digest: envelope.request.request_digest()?,
                        authorization_digest: envelope.request.authorization_digest,
                        issuer_id: envelope.request.issuer_id,
                        provider_id: envelope.request.provider_id,
                        account_id: envelope.request.account_id,
                        unit: envelope.request.unit,
                        available_value: state.available_value,
                        reserved_value: state.reserved_value,
                        ledger_sequence: state.ledger_sequence,
                        as_of_unix: now,
                        signature: [0; 64],
                    },
                    &self.issuer_settlement,
                )?;
                if state.corrupt_next_balance_response {
                    state.corrupt_next_balance_response = false;
                    response.request_digest = [0xee; 32];
                }
                response.encode()
            }
            PROVIDER_PAYOUT_INTENT_ENDPOINT_V1 => {
                let envelope = ProviderPayoutIntentEnvelopeV1::decode(body)?;
                verify_new_payout_intent_request_for(
                    &envelope.request,
                    &self.registration.payout_target_id,
                    &self.authorization,
                    &self.approval,
                    &envelope.request_auth,
                    &self.expectation(now),
                )?;
                prepare_payout_intent_response_v1(
                    &envelope.request,
                    2,
                    now + 100,
                    &self.issuer_settlement,
                )
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "FakeIssuer.payout_intent",
                    reason: "could not prepare payout intent",
                })?
                .encode()
            }
            PROVIDER_PAYOUT_ENDPOINT_V1 => {
                let envelope = ProviderPayoutEnvelopeV1::decode(body)?;
                let context = PayoutExecutionContextV1 {
                    intent_request: &envelope.intent_request,
                    intent_response: &envelope.intent_response,
                    registered_payout_target_id: &self.registration.payout_target_id,
                };
                let execution = verify_new_payout_request_for(
                    &envelope.request,
                    &context,
                    &self.authorization,
                    &self.approval,
                    &envelope.request_auth,
                    &self.expectation(now),
                )?;
                let mut committer = FakePayoutCommitter { state };
                let response = sign_and_commit_payout_execution_v1(
                    &execution,
                    now,
                    &self.issuer_settlement,
                    &mut committer,
                )
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "FakeIssuer.payout",
                    reason: "could not commit payout",
                })?;
                let keyring = IssuerSettlementKeyringExpectationV1 {
                    issuer_id: &ISSUER_ID,
                    current_key: &self.issuer_settlement_key,
                    retained_keys: &[],
                };
                let snapshot = verify_payout_initial_response_for_exact_request(
                    &response,
                    &envelope.request,
                    &keyring,
                )?;
                state.payout_request = Some(envelope.request);
                state.initial_payout_response = Some(response.clone());
                state.payout_snapshot = Some(snapshot);
                response.encode()
            }
            PROVIDER_PAYOUT_STATUS_ENDPOINT_V1 => {
                let envelope = ProviderPayoutStatusEnvelopeV1::decode(body)?;
                let requested_next_state = state.next_status_state.take();
                let initial = state.initial_payout_response.as_ref().ok_or(
                    ServiceProtocolError::InvalidValue {
                        field: "FakeIssuer.payout_status",
                        reason: "missing initial payout",
                    },
                )?;
                let previous =
                    state
                        .payout_snapshot
                        .as_ref()
                        .ok_or(ServiceProtocolError::InvalidValue {
                            field: "FakeIssuer.payout_status",
                            reason: "missing payout snapshot",
                        })?;
                let registration = ProviderSettlementRegistrationExpectationV1 {
                    registration_digest: &self.registration.registration_digest,
                    provider_id: &self.registration.provider_id,
                    issuer_id: &self.registration.issuer_id,
                    settlement_account_id: &self.registration.settlement_account_id,
                    provider_request_key: &self.provider_request_key,
                    issuer_settlement_key: &self.issuer_settlement_key,
                    not_before: self.registration.not_before,
                    not_after: self.registration.not_after,
                    now_unix: now,
                };
                let keyring = IssuerSettlementKeyringExpectationV1 {
                    issuer_id: &ISSUER_ID,
                    current_key: &self.issuer_settlement_key,
                    retained_keys: &[],
                };
                let context = PayoutStatusContextV1 {
                    payout_request: &envelope.payout_request,
                    initial_payout_response: &envelope.initial_payout_response,
                };
                verify_new_payout_status_request_for(
                    &envelope.request,
                    &context,
                    &envelope.request_auth,
                    &registration,
                    &keyring,
                )?;
                let mut committer = AlwaysCommitStatus;
                let next_state = requested_next_state.unwrap_or(previous.state());
                let response = sign_and_commit_payout_status_v1(
                    &envelope.request,
                    initial,
                    previous,
                    next_state,
                    now,
                    &self.issuer_settlement,
                    &mut committer,
                )
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "FakeIssuer.payout_status",
                    reason: "could not commit payout status",
                })?;
                let snapshot = verify_new_payout_status_response_for(
                    &response,
                    &envelope.request,
                    &context,
                    previous,
                    &envelope.request_auth,
                    &registration,
                    &keyring,
                )?;
                state.payout_snapshot = Some(snapshot);
                response.encode()
            }
            _ => Err(ServiceProtocolError::InvalidValue {
                field: "FakeIssuer.endpoint",
                reason: "unknown endpoint",
            }),
        }
    }
}

impl ProviderSettlementTransportV1 for FakeIssuer {
    fn post(
        &self,
        request: ProviderSettlementHttpRequestV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, ProviderSettlementTransportErrorV1> {
        assert_eq!(
            max_response_bytes,
            MAX_PROVIDER_SETTLEMENT_RESPONSE_BYTES_V1
        );
        let key = (request.endpoint.to_owned(), request.canonical_body.to_vec());
        let mut state = self.state.lock().expect("fake issuer lock");
        if request.endpoint == PROVIDER_PAYOUT_ENDPOINT_V1 {
            state.payout_posts.push(request.canonical_body.to_vec());
        }
        if let Some(exact) = state.exact_responses.get(&key) {
            return Ok(exact.clone());
        }
        let response = self
            .generate(request.endpoint, request.canonical_body, &mut state)
            .map_err(|_| ProviderSettlementTransportErrorV1::Rejected { status: 401 })?;
        state.exact_responses.insert(key, response.clone());
        if request.endpoint == PROVIDER_PAYOUT_ENDPOINT_V1 && state.lose_next_payout_response {
            state.lose_next_payout_response = false;
            return Err(ProviderSettlementTransportErrorV1::OutcomeUnknown);
        }
        if request.endpoint == PROVIDER_PAYOUT_STATUS_ENDPOINT_V1 && state.lose_next_status_response
        {
            state.lose_next_status_response = false;
            return Err(ProviderSettlementTransportErrorV1::OutcomeUnknown);
        }
        Ok(response)
    }
}

struct FakePayoutCommitter<'a> {
    state: &'a mut FakeIssuerState,
}

impl PayoutExecutionCommitStoreV1 for FakePayoutCommitter<'_> {
    type Error = &'static str;

    fn commit_new_payout(
        &mut self,
        execution: &VerifiedPayoutExecutionV1<'_>,
        _signed_response: &IssuerPayoutResponseV1,
    ) -> Result<bool, Self::Error> {
        let debit = execution.request().total_debit;
        if self.state.available_value < debit {
            return Ok(false);
        }
        self.state.available_value -= debit;
        self.state.reserved_value += debit;
        self.state.ledger_sequence += 1;
        self.state.intent_consume_count += 1;
        self.state.payout_debit_count += 1;
        self.state.outbox_insert_count += 1;
        Ok(true)
    }
}

struct AlwaysCommitStatus;

impl PayoutStatusCompareAndSwapStoreV1 for AlwaysCommitStatus {
    type Error = &'static str;

    fn compare_and_swap_payout_status(
        &mut self,
        _predecessor: &PayoutStatusCasExpectationV1,
        _signed_successor: &IssuerPayoutStatusResponseV1,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[test]
fn ledger_only_balance_client_needs_no_payout_registration_and_handles_key_rotation() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    issuer.commit_verified_redeem_credit(10, 9, 1);

    let current = fixture.ledger_client(
        fixture.issuer_settlement.verifying_key(),
        Vec::new(),
        &issuer,
    );
    assert_eq!(
        current.authorized_issuer_endpoint(),
        fixture.authorization.claims.redeem_endpoint
    );
    assert_eq!(
        current.authorized_leaf_spki_sha256_pins(),
        fixture.authorization.claims.redeem_leaf_spki_sha256_pins
    );
    let balance = current
        .balance([0x48; 32], NOW)
        .expect("signed ledger balance");
    assert_eq!((balance.available_value, balance.reserved_value), (9, 0));

    // During an issuer settlement-key rotation, an approval/response signed by
    // the historical key remains verifiable only when that exact key is
    // explicitly retained. No payout registration or provider-request key is
    // synthesized for this read-only path.
    let rotated = fixture.ledger_client(
        fixture.rotated_issuer_settlement.verifying_key(),
        vec![fixture.issuer_settlement.verifying_key()],
        &issuer,
    );
    rotated
        .balance([0x49; 32], NOW)
        .expect("retained issuer key verifies signed balance");

    issuer.corrupt_next_balance_response();
    assert!(matches!(
        rotated.balance([0x4a; 32], NOW),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    assert!(matches!(
        rotated.balance([0x4b; 32], 2_001),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));
}

#[test]
fn ledger_only_balance_client_rejects_key_reuse_and_missing_rotation_pin() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let trust = || ProviderLedgerBalanceTrustV1 {
        authorization: fixture.authorization.clone(),
        issuer_approval: fixture.approval.clone(),
        operator_verifying_key: fixture.operator.verifying_key(),
        minimum_authorization_epoch: 1,
        current_issuer_settlement_key: fixture.issuer_settlement.verifying_key(),
        retained_issuer_settlement_keys: Vec::new(),
    };
    assert!(
        ProviderLedgerBalanceClientV1::new(trust(), fixture.operator.clone(), &issuer,).is_err()
    );

    let mut no_floor = trust();
    no_floor.minimum_authorization_epoch = 0;
    assert!(
        ProviderLedgerBalanceClientV1::new(no_floor, fixture.clearing.clone(), &issuer).is_err()
    );

    let missing_old_key = ProviderLedgerBalanceTrustV1 {
        current_issuer_settlement_key: fixture.rotated_issuer_settlement.verifying_key(),
        ..trust()
    };
    assert!(
        ProviderLedgerBalanceClientV1::new(missing_old_key, fixture.clearing.clone(), &issuer,)
            .is_err()
    );

    let issuer_reuses_operator = ProviderLedgerBalanceTrustV1 {
        current_issuer_settlement_key: fixture.operator.verifying_key(),
        ..trust()
    };
    assert!(ProviderLedgerBalanceClientV1::new(
        issuer_reuses_operator,
        fixture.clearing.clone(),
        &issuer,
    )
    .is_err());

    let retained_reuses_operator = ProviderLedgerBalanceTrustV1 {
        retained_issuer_settlement_keys: vec![fixture.operator.verifying_key()],
        ..trust()
    };
    assert!(ProviderLedgerBalanceClientV1::new(
        retained_reuses_operator,
        fixture.clearing.clone(),
        &issuer,
    )
    .is_err());
}

#[test]
fn settlement_client_executes_credit_balance_payout_and_expired_exact_status_replay() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    let mut store = MemoryProviderStore::default();

    // Deterministic fake of the ledger transition after one credential has
    // already passed shared-issuer redeem verification.
    issuer.commit_verified_redeem_credit(10, 9, 1);

    let balance = client
        .balance(SettlementUnitV1::AuthCredit, [0x51; 32])
        .expect("balance after deterministic redeem credit");
    assert_eq!((balance.available_value, balance.reserved_value), (9, 0));

    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x52; 32])
        .expect("payout intent");
    assert_eq!(
        (intent.response().issuer_fee, intent.response().total_debit),
        (2, 9)
    );
    let payout = client
        .prepare_payout(&intent, [0x53; 32], NOW + 10, &mut store)
        .and_then(|pending| client.submit_payout(&pending, &mut store))
        .expect("persisted payout");
    assert_eq!(payout.snapshot().state(), PayoutStateV1::Accepted);
    assert_eq!(store.floor, Some(payout.rollback_floor()));
    let reserved = client
        .balance(SettlementUnitV1::AuthCredit, [0x55; 32])
        .expect("balance after payout reservation");
    assert_eq!((reserved.available_value, reserved.reserved_value), (0, 9));

    issuer.lose_next_status_response();
    let pending = client
        .prepare_payout_status(&payout, [0x54; 32], NOW + 10, &mut store)
        .expect("persist status before send");
    let first = client.submit_payout_status(&payout, &pending, &mut store);
    assert!(matches!(
        first,
        Err(ProviderSettlementStateErrorV1::Client(
            ProviderSettlementClientErrorV1::Transport(
                ProviderSettlementTransportErrorV1::OutcomeUnknown
            )
        ))
    ));
    assert_eq!(store.pending.as_ref(), Some(pending.pending()));

    // The issuer's exact cache is consulted after its ordinary registration
    // validity has elapsed. The client verifies the persisted historical
    // request rather than incorrectly treating this as a fresh request. A
    // simultaneously rotated client trust root accepts the cached response
    // only through the explicitly retained old issuer settlement key.
    issuer.expire_clock();
    let rotated_key_client = ProviderSettlementClientV1::new(
        fixture.trust(
            fixture.registration.clone(),
            fixture.rotated_issuer_settlement.verifying_key(),
            vec![fixture.issuer_settlement.verifying_key()],
            Vec::new(),
        ),
        fixture.clearing.clone(),
        fixture.provider_request.clone(),
        &issuer,
    )
    .expect("rotated-key client");
    let recovered = rotated_key_client
        .submit_payout_status(&payout, &pending, &mut store)
        .expect("same-nonce exact replay after expiry");
    assert_eq!(recovered.snapshot().state_version(), 2);
    assert!(store.pending.is_none());

    // A persisted request is bound to its predecessor floor and cannot be
    // reused after the response has been accepted.
    assert!(matches!(
        rotated_key_client.submit_payout_status(&recovered, &pending, &mut store),
        Err(ProviderSettlementStateErrorV1::Client(
            ProviderSettlementClientErrorV1::Rollback
        ))
    ));
}

#[test]
fn key_and_registration_rotation_restore_and_rollback_checks_fail_closed() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    let mut store = MemoryProviderStore::default();
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x61; 32])
        .expect("intent");
    let payout = client
        .prepare_payout(&intent, [0x62; 32], NOW + 10, &mut store)
        .and_then(|pending| client.submit_payout(&pending, &mut store))
        .expect("payout");
    let pending = client
        .prepare_payout_status(&payout, [0x63; 32], NOW + 10, &mut store)
        .expect("pending status");
    let version_two = client
        .submit_payout_status(&payout, &pending, &mut store)
        .expect("version two");
    let version_two_durable = version_two.durable_state().expect("durable v2");
    let pending_three = client
        .prepare_payout_status(&version_two, [0x64; 32], NOW + 20, &mut store)
        .expect("fresh status");
    let version_three = client
        .submit_payout_status(&version_two, &pending_three, &mut store)
        .expect("version three");
    assert_eq!(version_three.snapshot().state_version(), 3);

    let rotated_registration = ProviderSettlementRegistrationV1 {
        registration_digest: ROTATED_REGISTRATION_DIGEST,
        not_after: 4_000,
        ..fixture.registration.clone()
    };
    let rotated_client = ProviderSettlementClientV1::new(
        fixture.trust(
            rotated_registration,
            fixture.rotated_issuer_settlement.verifying_key(),
            vec![fixture.issuer_settlement.verifying_key()],
            vec![fixture.registration.clone()],
        ),
        fixture.clearing.clone(),
        fixture.provider_request.clone(),
        &issuer,
    )
    .expect("rotated client");
    let restored = rotated_client
        .restore_payout(&version_two_durable, &version_two.rollback_floor())
        .expect("historical issuer key and registration restore");
    assert_eq!(restored.snapshot().state_version(), 2);
    // The fake issuer still signs with the retained old key; the rotated
    // client accepts it only through the configured issuer key lineage.
    rotated_client
        .balance(SettlementUnitV1::AuthCredit, [0x65; 32])
        .expect("retained issuer response key");
    assert!(matches!(
        rotated_client.restore_payout(&version_two_durable, &version_three.rollback_floor()),
        Err(ProviderSettlementClientErrorV1::Rollback)
    ));

    // The floor sequence, not wall-clock granularity, is authoritative.
    let mut same_second_successor = version_two.rollback_floor();
    same_second_successor.state = PayoutStateV1::InFlight;
    same_second_successor.state_version += 1;
    assert!(floor_is_satisfied(
        &version_two.rollback_floor(),
        &same_second_successor
    ));
}

#[test]
fn request_and_response_digest_tampering_and_wrong_provider_key_are_rejected() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    issuer.corrupt_next_balance_response();
    assert!(matches!(
        client.balance(SettlementUnitV1::AuthCredit, [0x71; 32]),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    let mut wrong_registration = fixture.registration.clone();
    wrong_registration.provider_request_verifying_key = [0x72; 32];
    assert!(ProviderSettlementClientV1::new(
        fixture.trust(
            wrong_registration,
            fixture.issuer_settlement.verifying_key(),
            Vec::new(),
            Vec::new(),
        ),
        fixture.clearing.clone(),
        fixture.provider_request.clone(),
        &issuer,
    )
    .is_err());

    let mut store = MemoryProviderStore::default();
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x73; 32])
        .expect("intent");
    let payout = client
        .prepare_payout(&intent, [0x74; 32], NOW + 10, &mut store)
        .and_then(|pending| client.submit_payout(&pending, &mut store))
        .expect("payout");
    let pending = client
        .prepare_payout_status(&payout, [0x75; 32], NOW + 10, &mut store)
        .expect("pending");
    let mut tampered = pending.pending().clone();
    tampered.request_digest = [0x76; 32];
    assert!(matches!(
        client.restore_persisted_payout_status(&payout, tampered),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));
    let mut tampered_auth = pending.pending().clone();
    let mut envelope = ProviderPayoutStatusEnvelopeV1::decode(&tampered_auth.canonical_envelope)
        .expect("pending envelope");
    envelope.request_auth.request_digest = [0x77; 32];
    tampered_auth.canonical_envelope = envelope.encode().expect("tampered auth envelope");
    assert!(matches!(
        client.restore_persisted_payout_status(&payout, tampered_auth),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));
}

#[test]
fn payout_replay_authority_is_redacted_from_debug() {
    const SENTINEL: &str = "signed-payout-replay-authority-sentinel";

    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    let mut store = MemoryProviderStore::default();
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x78; 32])
        .expect("intent");
    let persisted = client
        .prepare_payout(&intent, [0x79; 32], NOW + 10, &mut store)
        .expect("pending payout");
    let payout = client
        .submit_payout(&persisted, &mut store)
        .expect("payout");
    let persisted_status = client
        .prepare_payout_status(&payout, [0x7a; 32], NOW + 11, &mut store)
        .expect("pending status");

    let mut raw_pending = persisted.pending().clone();
    raw_pending.canonical_envelope = SENTINEL.as_bytes().to_vec();
    raw_pending.intent_request = SENTINEL.as_bytes().to_vec();
    let mut raw_state = payout.durable_state().expect("durable payout");
    raw_state.payout_request = SENTINEL.as_bytes().to_vec();
    let mut raw_status = persisted_status.pending().clone();
    raw_status.canonical_envelope = SENTINEL.as_bytes().to_vec();
    let recovery = ProviderSettlementRecoveryV1 {
        active_pending_payout: Some(raw_pending.clone()),
        committed_payout_origin: Some(raw_pending.clone()),
        payout_state: Some(raw_state.clone()),
        pending_status: Some(raw_status.clone()),
    };

    for debug in [
        format!("{raw_pending:?}"),
        format!("{raw_state:?}"),
        format!("{raw_status:?}"),
        format!("{recovery:?}"),
        format!("{persisted:?}"),
        format!("{persisted_status:?}"),
    ] {
        assert!(!debug.contains(SENTINEL));
    }
}

#[test]
fn initial_payout_is_persisted_before_send_and_exactly_recovers_after_response_loss() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    let mut store = MemoryProviderStore::default();
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x81; 32])
        .expect("payout intent");

    let pending = client
        .prepare_payout(&intent, [0x82; 32], NOW + 10, &mut store)
        .expect("pending payout persisted");
    let durable_pending = pending.pending().clone();
    let independent_floor = durable_pending.pending_floor;
    assert!(issuer.payout_posts().is_empty());
    assert_eq!(store.pending_payout.as_ref(), Some(&durable_pending));
    assert_eq!(store.pending_floor, Some(independent_floor));

    issuer.lose_next_payout_response();
    let first = client.submit_payout(&pending, &mut store);
    assert!(matches!(
        first,
        Err(ProviderSettlementStateErrorV1::Client(
            ProviderSettlementClientErrorV1::Transport(
                ProviderSettlementTransportErrorV1::OutcomeUnknown
            )
        ))
    ));
    assert_eq!(store.pending_payout.as_ref(), Some(&durable_pending));
    assert_eq!(store.pending_floor, Some(independent_floor));
    assert_eq!(issuer.payout_economic_counts(), (1, 1, 1));

    // Simulate both a process restart and current registration/key rotation.
    // Only the exact pending bytes plus the independent floor unlock the
    // historical current-or-retained validation path.
    let rotated_registration = ProviderSettlementRegistrationV1 {
        registration_digest: ROTATED_REGISTRATION_DIGEST,
        not_after: 4_000,
        ..fixture.registration.clone()
    };
    let restarted = ProviderSettlementClientV1::new(
        fixture.trust(
            rotated_registration,
            fixture.rotated_issuer_settlement.verifying_key(),
            vec![fixture.issuer_settlement.verifying_key()],
            vec![fixture.registration.clone()],
        ),
        fixture.clearing.clone(),
        fixture.provider_request.clone(),
        &issuer,
    )
    .expect("rotated restart client");
    let restored = restarted
        .restore_persisted_payout(durable_pending, &independent_floor)
        .expect("exact pending restore");
    let payout = restarted
        .submit_payout(&restored, &mut store)
        .expect("exact response-loss retry");
    assert_eq!(payout.snapshot().state(), PayoutStateV1::Accepted);
    let posts = issuer.payout_posts();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
    assert_eq!(issuer.payout_economic_counts(), (1, 1, 1));
    assert!(store.pending_payout.is_none());
    assert!(store.pending_floor.is_none());
    assert_eq!(store.floor, Some(payout.rollback_floor()));
}

#[test]
fn pending_payout_restore_rejects_tamper_wrong_intent_floor_and_stale_fresh_time() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x83; 32])
        .expect("payout intent");
    let other_intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 6, [0x84; 32])
        .expect("different signed payout intent");
    let mut store = MemoryProviderStore::default();
    let marker = client
        .prepare_payout(&intent, [0x85; 32], NOW + 10, &mut store)
        .expect("pending payout");
    let original = marker.pending().clone();

    let mut wrong_floor = original.pending_floor;
    wrong_floor.pending_digest[0] ^= 1;
    assert!(matches!(
        client.restore_persisted_payout(original.clone(), &wrong_floor),
        Err(ProviderSettlementClientErrorV1::Rollback)
    ));

    let mut wrong_intent = original.clone();
    wrong_intent.intent_request = other_intent.request().encode().expect("other request");
    wrong_intent.intent_response = other_intent.response().encode().expect("other response");
    recompute_pending_floor(&mut wrong_intent);
    let wrong_intent_floor = wrong_intent.pending_floor;
    assert!(matches!(
        client.restore_persisted_payout(wrong_intent, &wrong_intent_floor),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    let mut wrong_digest = original.clone();
    wrong_digest.payout_request_digest[0] ^= 1;
    recompute_pending_floor(&mut wrong_digest);
    let wrong_digest_floor = wrong_digest.pending_floor;
    assert!(matches!(
        client.restore_persisted_payout(wrong_digest, &wrong_digest_floor),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    let mut wrong_idempotency = original.clone();
    wrong_idempotency.idempotency_key[0] ^= 1;
    recompute_pending_floor(&mut wrong_idempotency);
    let wrong_idempotency_floor = wrong_idempotency.pending_floor;
    assert!(matches!(
        client.restore_persisted_payout(wrong_idempotency, &wrong_idempotency_floor),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    let mut wrong_registration = original.clone();
    wrong_registration.registration.registration_digest[0] ^= 1;
    recompute_pending_floor(&mut wrong_registration);
    let wrong_registration_floor = wrong_registration.pending_floor;
    assert!(matches!(
        client.restore_persisted_payout(wrong_registration, &wrong_registration_floor),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    let mut wrong_envelope = original.clone();
    wrong_envelope.canonical_envelope[0] ^= 1;
    recompute_pending_floor(&mut wrong_envelope);
    let wrong_envelope_floor = wrong_envelope.pending_floor;
    assert!(matches!(
        client.restore_persisted_payout(wrong_envelope, &wrong_envelope_floor),
        Err(ProviderSettlementClientErrorV1::Protocol(_))
    ));

    let mut stale_store = MemoryProviderStore::default();
    assert!(matches!(
        client.prepare_payout(&intent, [0x86; 32], 2_001, &mut stale_store),
        Err(ProviderSettlementStateErrorV1::Client(
            ProviderSettlementClientErrorV1::Protocol(_)
        ))
    ));
    assert!(stale_store.pending_payout.is_none());
    assert!(issuer.payout_posts().is_empty());
}

#[test]
fn independent_pending_floor_blocks_detailed_store_rollback_and_replacement() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x87; 32])
        .expect("payout intent");
    let mut store = MemoryProviderStore::default();
    let marker = client
        .prepare_payout(&intent, [0x88; 32], NOW + 10, &mut store)
        .expect("pending payout");

    // Detailed pending state was rolled back, but the independent authority
    // still names it. Neither a replacement nor the old marker may reach the
    // issuer until the exact detailed record is recovered.
    store.pending_payout = None;
    assert!(store.pending_floor.is_some());
    assert!(matches!(
        client.prepare_payout(&intent, [0x89; 32], NOW + 11, &mut store),
        Err(ProviderSettlementStateErrorV1::Conflict { .. })
    ));
    assert!(matches!(
        client.submit_payout(&marker, &mut store),
        Err(ProviderSettlementStateErrorV1::Conflict { .. })
    ));
    assert!(issuer.payout_posts().is_empty());
    assert_eq!(issuer.payout_economic_counts(), (0, 0, 0));
}

#[test]
fn terminal_predecessor_chain_allows_repeated_payouts_but_rejects_old_generation() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    let mut store = MemoryProviderStore::default();
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let first_intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x90; 32])
        .expect("first payout intent");
    let first_marker = client
        .prepare_payout(&first_intent, [0x91; 32], NOW + 10, &mut store)
        .expect("first pending payout");
    let first = client
        .submit_payout(&first_marker, &mut store)
        .expect("first payout");

    let second_intent_too_early = client
        .payout_intent(SettlementUnitV1::AuthCredit, 1, [0x92; 32])
        .expect("second intent before terminal state");
    assert!(matches!(
        client.prepare_next_payout(
            &second_intent_too_early,
            [0x93; 32],
            NOW + 11,
            &first,
            &mut store,
        ),
        Err(ProviderSettlementStateErrorV1::Client(
            ProviderSettlementClientErrorV1::Protocol(_)
        ))
    ));

    issuer.set_next_status_state(PayoutStateV1::InFlight);
    let first_in_flight_pending = client
        .prepare_payout_status(&first, [0x94; 32], NOW + 12, &mut store)
        .expect("first in-flight status pending");
    let first_in_flight = client
        .submit_payout_status(&first, &first_in_flight_pending, &mut store)
        .expect("first payout in-flight");
    issuer.set_next_status_state(PayoutStateV1::Succeeded);
    let first_terminal_pending = client
        .prepare_payout_status(&first_in_flight, [0x95; 32], NOW + 13, &mut store)
        .expect("first terminal status pending");
    let first_terminal = client
        .submit_payout_status(&first_in_flight, &first_terminal_pending, &mut store)
        .expect("first payout succeeded");
    assert_eq!(first_terminal.snapshot().state(), PayoutStateV1::Succeeded);
    let first_terminal_state = store.state.clone().expect("terminal durable state");

    issuer.commit_verified_redeem_credit(10, 9, 1);
    let second_intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0x96; 32])
        .expect("second payout intent");
    let second_marker = client
        .prepare_next_payout(
            &second_intent,
            [0x97; 32],
            NOW + 14,
            &first_terminal,
            &mut store,
        )
        .expect("second payout chained from terminal floor");
    assert_eq!(
        second_marker.pending().predecessor_floor,
        Some(first_terminal.rollback_floor())
    );
    assert_eq!(store.history, vec![first_terminal_state.clone()]);
    assert_eq!(store.pending_history.len(), 1);
    assert_eq!(
        store.pending_history[0].pending_floor,
        store
            .committed_pending
            .as_ref()
            .expect("first committed pending metadata")
            .pending_floor
    );
    let second = client
        .submit_payout(&second_marker, &mut store)
        .expect("second payout");
    assert_eq!(second.snapshot().state(), PayoutStateV1::Accepted);
    assert_eq!(issuer.payout_economic_counts(), (2, 2, 2));

    // Roll the detailed current row back to the first terminal payout while
    // retaining the independent second-payout floor. The stale predecessor
    // cannot create a third request or overwrite the newer generation.
    store.state = Some(first_terminal_state);
    let third_intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 1, [0x98; 32])
        .expect("third payout intent");
    assert!(matches!(
        client.prepare_next_payout(
            &third_intent,
            [0x99; 32],
            NOW + 15,
            &first_terminal,
            &mut store,
        ),
        Err(ProviderSettlementStateErrorV1::Conflict { .. })
    ));
    assert_eq!(issuer.payout_economic_counts(), (2, 2, 2));
}

#[test]
fn concurrent_exact_submit_creates_one_economic_payout() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0xa1; 32])
        .expect("payout intent");
    let shared = SharedMemoryProviderStore::default();
    let mut preparing_store = shared.clone();
    let marker = client
        .prepare_payout(&intent, [0xa2; 32], NOW + 10, &mut preparing_store)
        .expect("pending payout");
    let marker_two = marker.clone();
    let mut store_one = shared.clone();
    let mut store_two = shared.clone();
    let client_ref = &client;
    let (first, second) = std::thread::scope(|scope| {
        let one = scope.spawn(|| client_ref.submit_payout(&marker, &mut store_one));
        let two = scope.spawn(|| client_ref.submit_payout(&marker_two, &mut store_two));
        (
            one.join().expect("first submit thread"),
            two.join().expect("second submit thread"),
        )
    });
    assert!(first.is_ok() || second.is_ok());
    assert!(first.is_ok() || matches!(first, Err(ProviderSettlementStateErrorV1::Conflict { .. })));
    assert!(
        second.is_ok() || matches!(second, Err(ProviderSettlementStateErrorV1::Conflict { .. }))
    );
    assert_eq!(issuer.payout_economic_counts(), (1, 1, 1));
    let posts = issuer.payout_posts();
    assert!((1..=2).contains(&posts.len()));
    assert!(posts.windows(2).all(|pair| pair[0] == pair[1]));
    let final_store = shared.0.lock().expect("final provider store");
    assert!(final_store.state.is_some());
    assert!(final_store.pending_payout.is_none());
    assert!(final_store.pending_floor.is_none());
}

#[test]
fn recovery_rejects_valid_status_response_for_another_nonce_without_authority_change() {
    let fixture = Fixture::new();
    let issuer = FakeIssuer::new(&fixture);
    let client = fixture.client(&issuer);
    let mut base_store = MemoryProviderStore::default();
    issuer.commit_verified_redeem_credit(10, 9, 1);
    let intent = client
        .payout_intent(SettlementUnitV1::AuthCredit, 7, [0xb1; 32])
        .expect("payout intent");
    let payout = client
        .prepare_payout(&intent, [0xb2; 32], NOW + 10, &mut base_store)
        .and_then(|pending| client.submit_payout(&pending, &mut base_store))
        .expect("accepted payout");
    let previous_state = payout.durable_state().expect("previous durable payout");
    let origin = base_store
        .committed_pending
        .clone()
        .expect("committed payout origin");

    let mut request_a_store = MemoryProviderStore {
        state: Some(previous_state.clone()),
        floor: Some(payout.rollback_floor()),
        committed_pending: Some(origin.clone()),
        ..MemoryProviderStore::default()
    };
    let request_a = client
        .prepare_payout_status(&payout, [0xb3; 32], NOW + 11, &mut request_a_store)
        .expect("first exact status request");

    let mut request_b_store = MemoryProviderStore {
        state: Some(previous_state.clone()),
        floor: Some(payout.rollback_floor()),
        committed_pending: Some(origin.clone()),
        ..MemoryProviderStore::default()
    };
    let request_b = client
        .prepare_payout_status(&payout, [0xb4; 32], NOW + 12, &mut request_b_store)
        .expect("second exact status request");
    issuer.set_next_status_state(PayoutStateV1::InFlight);
    let successor_b = client
        .submit_payout_status(&payout, &request_b, &mut request_b_store)
        .expect("valid response for second nonce")
        .durable_state()
        .expect("durable second-nonce response");

    let expected_floor = ProviderSettlementFloorV1 {
        store_instance_id: [0xc1; 16],
        provider_id: PROVIDER_ID,
        revision: 3,
        active_commitment: [0xc2; 32],
        history_length: 0,
        history_commitment: [0xc3; 32],
        phase: ProviderSettlementFloorPhaseV1::StatusPending {
            payout: payout.rollback_floor(),
        },
    };
    let desired_floor = ProviderSettlementFloorV1 {
        revision: 4,
        active_commitment: [0xc4; 32],
        phase: ProviderSettlementFloorPhaseV1::Payout {
            payout: successor_b.rollback_floor,
        },
        ..expected_floor
    };
    let inspection = UnverifiedProviderSettlementRecoveryV2 {
        snapshot_digest: [0xc5; 32],
        transition_kind: ProviderSettlementRecoveryTransitionKindV2::StatusCommit,
        workflow: ProviderSettlementRecoveryV1 {
            active_pending_payout: None,
            committed_payout_origin: Some(origin),
            payout_state: Some(successor_b),
            pending_status: Some(request_a.pending().clone()),
        },
        transition_previous_state: Some(previous_state),
        expected_floor: Some(expected_floor),
        desired_floor,
        authority_at_inspection: Some(expected_floor),
    };
    let authority_before = inspection.authority_at_inspection;

    assert!(client
        .authenticate_settlement_recovery_v2(&inspection)
        .is_err());
    assert_eq!(inspection.authority_at_inspection, authority_before);
}
