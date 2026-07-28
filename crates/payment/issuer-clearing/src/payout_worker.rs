use ed25519_dalek::{SigningKey, VerifyingKey};
use pir_issuer_store::{
    issuer_payout_outbox_command_id_v1, IssuerStore, PayoutOutboxCommandV1, PayoutOutboxStateV1,
    PayoutRecordV1, StoreError,
};
use pir_service_protocol::{
    verify_persisted_payout_snapshot_from_store_record_v1, IssuerPayoutResponseV1,
    IssuerPayoutStatusResponseV1, IssuerSettlementKeyringExpectationV1, PayoutCommitErrorV1,
    PayoutStateV1, ServiceProtocolError, SettlementUnitV1, VerifiedPayoutSnapshotV1,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const WORKER_STATUS_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-clearing/payout-worker-status-request/v1";
const WORKER_STATUS_REGISTRATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-clearing/payout-worker-registration/v1";
pub const MAX_PAYOUT_WORKER_LEASE_SECONDS_V1: u64 = 300;

/// Minimal command exposed to an external value-transfer adapter. The stable
/// `command_id` is the mandatory executor idempotency key. `payout_target_id`
/// is an opaque but stable provider payout-routing pseudonym and is therefore
/// linkable across payouts to the same target. It is not a raw provider
/// identity, and this command contains no invoice, payment hash, payer data, or
/// PIR query data. No command, payout, or target identifier may be logged.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExternalPayoutCommandV1 {
    pub command_id: [u8; 32],
    pub payout_id: [u8; 32],
    pub payout_target_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
}

impl From<&PayoutOutboxCommandV1> for ExternalPayoutCommandV1 {
    fn from(value: &PayoutOutboxCommandV1) -> Self {
        Self {
            command_id: value.command_id,
            payout_id: value.payout_id,
            payout_target_id: value.payout_target_id,
            unit: value.unit,
            payout_value: value.payout_value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalPayoutReadinessV1 {
    /// The adapter is intentionally disabled. The worker performs no store
    /// read, claim, or mutation in this state.
    Disabled,
    /// Configuration exists, but the adapter cannot currently prove it is
    /// ready. The worker performs no store read, claim, or mutation.
    Unavailable,
    Ready,
}

/// Result of either a first submission or a read-only reconciliation.
///
/// `DefinitelyFailed` is permitted only when the executor can prove that value
/// was not, and can no longer be, transferred for this command. The worker
/// ultimately maps timeouts, cancellation, disconnects, malformed replies,
/// process crashes, and ambiguous remote status to `OutcomeUnknown`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalPayoutOutcomeV1 {
    Succeeded,
    DefinitelyFailed,
    OutcomeUnknown,
}

/// Mandatory execution boundary for one external payout call.
///
/// The deadline is an absolute Unix timestamp derived from the durable outbox
/// lease and is always strictly earlier than that lease's expiry. An adapter
/// MUST apply it to the complete external operation, including name lookup,
/// connect, request, response and any status lookup it performs.
#[must_use = "the payout adapter must enforce this absolute deadline"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalPayoutExecutionContextV1 {
    absolute_deadline_unix: u64,
}

impl ExternalPayoutExecutionContextV1 {
    pub const fn absolute_deadline_unix(self) -> u64 {
        self.absolute_deadline_unix
    }
}

/// Adapter result before the worker applies its conservative ambiguity rule.
///
/// Timeout and cancellation are explicit so the worker, rather than each
/// adapter, structurally maps them to `OutcomeUnknown`.
#[must_use = "external payout call results must be reconciled or committed"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalPayoutCallResultV1 {
    Completed(ExternalPayoutOutcomeV1),
    TimedOut,
    Cancelled,
}

impl ExternalPayoutCallResultV1 {
    const fn conservative_outcome(self) -> ExternalPayoutOutcomeV1 {
        match self {
            Self::Completed(outcome) => outcome,
            Self::TimedOut | Self::Cancelled => ExternalPayoutOutcomeV1::OutcomeUnknown,
        }
    }
}

/// Real-funds integrations implement this trait in a separately reviewed
/// adapter. V1 intentionally ships no enabled real-funds implementation.
///
/// The issuer SQLite transition and an external value-transfer system cannot
/// by themselves form one atomic transaction. Real-funds exactly-once safety
/// therefore depends on that external system providing a linearizable,
/// durable `command_id` lookup/submission primitive (or an equivalent
/// authoritative no-submit fence). This worker deliberately does not claim to
/// manufacture exactly-once semantics from a best-effort adapter.
pub trait ExternalPayoutExecutorV1 {
    fn readiness(&self) -> ExternalPayoutReadinessV1;

    /// Submit at most once for a command. Implementations MUST bind the exact
    /// `command_id` to the external system's linearizable durable idempotency
    /// facility. The method name is an adapter obligation, not a guarantee
    /// supplied by the worker across a process crash.
    /// The adapter MUST enforce `context.absolute_deadline_unix()` across the
    /// whole operation. Deadline expiry and caller/process cancellation MUST
    /// return `TimedOut` or `Cancelled`; neither is evidence of rejection.
    fn submit_once(
        &mut self,
        command: &ExternalPayoutCommandV1,
        context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1;

    /// Reconcile only the already-submitted command's status. This method MUST
    /// NOT initiate or repeat a value transfer. It may install an authoritative
    /// no-submit fence/tombstone when the external system supports that atomic
    /// operation; without such a fence, an absent command remains unknown.
    /// The same absolute-deadline and ambiguity rules as `submit_once` apply.
    fn reconcile(
        &mut self,
        command: &ExternalPayoutCommandV1,
        context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1;
}

/// Safe default executor. It cannot be switched to ready and therefore cannot
/// claim an outbox row or move provider funds between ledger states.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFundsPayoutExecutorV1;

impl ExternalPayoutExecutorV1 for NoFundsPayoutExecutorV1 {
    fn readiness(&self) -> ExternalPayoutReadinessV1 {
        ExternalPayoutReadinessV1::Disabled
    }

    fn submit_once(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        _context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        ExternalPayoutCallResultV1::Cancelled
    }

    fn reconcile(
        &mut self,
        _command: &ExternalPayoutCommandV1,
        _context: ExternalPayoutExecutionContextV1,
    ) -> ExternalPayoutCallResultV1 {
        ExternalPayoutCallResultV1::Cancelled
    }
}

/// Injectable clock so tests can exercise strict timestamp monotonicity
/// without sleeping. A missing/zero/non-increasing time always defers work.
pub trait PayoutWorkerClockV1 {
    fn now_unix(&mut self) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemPayoutWorkerClockV1;

impl PayoutWorkerClockV1 for SystemPayoutWorkerClockV1 {
    fn now_unix(&mut self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
            .filter(|value| *value != 0)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PayoutOutboxWorkerProgressV1 {
    ExecutorDisabled,
    ExecutorUnavailable,
    Idle,
    /// No external call was made because the durable transition timestamp
    /// could not advance monotonically.
    DeferredForClock {
        payout_id: [u8; 32],
        state: PayoutStateV1,
    },
    /// Submission or reconciliation was ambiguous. The payout remains
    /// InFlight and future workers may reconcile, but never resubmit it.
    OutcomeUnknown {
        payout_id: [u8; 32],
    },
    /// The external outcome is known, but a later monotonic timestamp is
    /// required before the terminal CAS can be signed and committed.
    TerminalCommitDeferred {
        payout_id: [u8; 32],
        outcome: ExternalPayoutOutcomeV1,
    },
    Succeeded {
        payout_id: [u8; 32],
    },
    Failed {
        payout_id: [u8; 32],
    },
    /// Another worker won an exact predecessor CAS. No external submission is
    /// attempted after this result.
    ConcurrentAdvance {
        payout_id: [u8; 32],
    },
    /// An external outcome exists, but another signed status successor won the
    /// terminal CAS. The command must be reconciled later; it must not be
    /// submitted again.
    TerminalCommitRaced {
        payout_id: [u8; 32],
        outcome: ExternalPayoutOutcomeV1,
    },
}

impl fmt::Debug for PayoutOutboxWorkerProgressV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecutorDisabled => formatter.write_str("ExecutorDisabled"),
            Self::ExecutorUnavailable => formatter.write_str("ExecutorUnavailable"),
            Self::Idle => formatter.write_str("Idle"),
            Self::DeferredForClock { state, .. } => formatter
                .debug_tuple("DeferredForClock")
                .field(state)
                .finish(),
            Self::OutcomeUnknown { .. } => formatter.write_str("OutcomeUnknown"),
            Self::TerminalCommitDeferred { outcome, .. } => formatter
                .debug_tuple("TerminalCommitDeferred")
                .field(outcome)
                .finish(),
            Self::Succeeded { .. } => formatter.write_str("Succeeded"),
            Self::Failed { .. } => formatter.write_str("Failed"),
            Self::ConcurrentAdvance { .. } => formatter.write_str("ConcurrentAdvance"),
            Self::TerminalCommitRaced { outcome, .. } => formatter
                .debug_tuple("TerminalCommitRaced")
                .field(outcome)
                .finish(),
        }
    }
}

#[derive(Debug)]
pub enum PayoutOutboxWorkerErrorV1 {
    InvalidConfiguration(&'static str),
    ClockUnavailable,
    Store(StoreError),
    Protocol(ServiceProtocolError),
    StoreInvariant(&'static str),
}

impl core::fmt::Display for PayoutOutboxWorkerErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => {
                write!(formatter, "invalid payout-worker configuration: {reason}")
            }
            Self::ClockUnavailable => formatter.write_str("payout-worker clock is unavailable"),
            Self::Store(error) => write!(formatter, "payout-worker store error: {error}"),
            Self::Protocol(error) => write!(formatter, "payout-worker protocol error: {error}"),
            Self::StoreInvariant(reason) => {
                write!(formatter, "payout-worker store invariant failed: {reason}")
            }
        }
    }
}

impl std::error::Error for PayoutOutboxWorkerErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidConfiguration(_) | Self::ClockUnavailable | Self::StoreInvariant(_) => {
                None
            }
        }
    }
}

impl From<StoreError> for PayoutOutboxWorkerErrorV1 {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<ServiceProtocolError> for PayoutOutboxWorkerErrorV1 {
    fn from(value: ServiceProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// One fail-closed issuer payout worker. A claimed Accepted payout is durably
/// moved to InFlight before `submit_once` is called. Every later claim of an
/// InFlight payout calls only `reconcile`, including after a crash or ambiguous
/// external response. This deliberately prefers a stranded payout requiring
/// operator reconciliation over a possible duplicate payment. A real-funds
/// adapter remains disabled until its `command_id` status/fence semantics have
/// been reviewed as the external exactly-once authority described above.
pub struct IssuerPayoutOutboxWorkerV1<'a, Executor> {
    store: &'a IssuerStore,
    issuer_settlement_signing_key: &'a SigningKey,
    retained_issuer_settlement_keys: &'a [VerifyingKey],
    executor: Executor,
    lease_owner: [u8; 32],
    lease_seconds: u64,
    external_call_timeout_seconds: u64,
}

struct VerifiedBoundPayoutV1 {
    record: PayoutRecordV1,
    snapshot: VerifiedPayoutSnapshotV1,
}

impl<'a, Executor: ExternalPayoutExecutorV1> IssuerPayoutOutboxWorkerV1<'a, Executor> {
    pub fn new(
        store: &'a IssuerStore,
        issuer_settlement_signing_key: &'a SigningKey,
        retained_issuer_settlement_keys: &'a [VerifyingKey],
        executor: Executor,
        lease_owner: [u8; 32],
        lease_seconds: u64,
        external_call_timeout_seconds: u64,
    ) -> Result<Self, PayoutOutboxWorkerErrorV1> {
        if lease_owner.iter().all(|byte| *byte == 0) {
            return Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(
                "lease owner is all zero",
            ));
        }
        if lease_seconds == 0 {
            return Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(
                "lease duration is zero",
            ));
        }
        if lease_seconds > MAX_PAYOUT_WORKER_LEASE_SECONDS_V1 {
            return Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(
                "lease duration exceeds the V1 bound",
            ));
        }
        if external_call_timeout_seconds == 0 {
            return Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(
                "external call timeout is zero",
            ));
        }
        if external_call_timeout_seconds >= lease_seconds {
            return Err(PayoutOutboxWorkerErrorV1::InvalidConfiguration(
                "external call timeout must be shorter than the durable lease",
            ));
        }
        Ok(Self {
            store,
            issuer_settlement_signing_key,
            retained_issuer_settlement_keys,
            executor,
            lease_owner,
            lease_seconds,
            external_call_timeout_seconds,
        })
    }

    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    pub fn executor_mut(&mut self) -> &mut Executor {
        &mut self.executor
    }

    pub fn run_once(
        &mut self,
        clock: &mut impl PayoutWorkerClockV1,
    ) -> Result<PayoutOutboxWorkerProgressV1, PayoutOutboxWorkerErrorV1> {
        match self.executor.readiness() {
            ExternalPayoutReadinessV1::Disabled => {
                return Ok(PayoutOutboxWorkerProgressV1::ExecutorDisabled)
            }
            ExternalPayoutReadinessV1::Unavailable => {
                return Ok(PayoutOutboxWorkerProgressV1::ExecutorUnavailable)
            }
            ExternalPayoutReadinessV1::Ready => {}
        }
        let claim_now = next_clock_value(clock)?;
        let Some(claimed) = self.store.claim_next_payout_outbox(
            &self.lease_owner,
            claim_now,
            self.lease_seconds,
        )?
        else {
            return Ok(PayoutOutboxWorkerProgressV1::Idle);
        };
        let claim_commit = claimed.commit;
        let outbox = claimed.value;
        if outbox.state != PayoutOutboxStateV1::Leased || outbox.lease_owner_digest.is_none() {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "claimed outbox command is not durably leased",
            ));
        }
        if outbox.commit != claim_commit {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "claimed outbox row is not the exact durable lease commit",
            ));
        }
        let lease_until = outbox
            .lease_until
            .ok_or(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "claimed outbox command has no durable lease expiry",
            ))?;
        let expected_lease_until = claim_now.checked_add(self.lease_seconds).ok_or(
            PayoutOutboxWorkerErrorV1::StoreInvariant("durable lease expiry overflows"),
        )?;
        if lease_until != expected_lease_until {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "claimed outbox lease expiry does not match this worker claim",
            ));
        }
        let absolute_deadline_unix = claim_now
            .checked_add(self.external_call_timeout_seconds)
            .ok_or(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "external call deadline overflows",
            ))?;
        if absolute_deadline_unix >= lease_until {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "external call deadline is not strictly inside the durable lease",
            ));
        }
        let execution_context = ExternalPayoutExecutionContextV1 {
            absolute_deadline_unix,
        };
        let command = ExternalPayoutCommandV1::from(&outbox);
        let verified = self.load_verified_bound_payout(&command)?;
        match verified.record.state {
            PayoutStateV1::Accepted => {
                let Some(updated_at) = monotonic_clock_value(clock, verified.record.updated_at)?
                else {
                    return Ok(PayoutOutboxWorkerProgressV1::DeferredForClock {
                        payout_id: command.payout_id,
                        state: verified.record.state,
                    });
                };
                let Some(committed_in_flight) =
                    self.advance_status(&verified, &command, PayoutStateV1::InFlight, updated_at)?
                else {
                    return Ok(PayoutOutboxWorkerProgressV1::ConcurrentAdvance {
                        payout_id: command.payout_id,
                    });
                };
                // Reload and authenticate the exact state that now authorizes
                // the external call. A successful predecessor CAS is not a
                // shortcut around checking the durably stored, current signed
                // snapshot and the configured current/retained key lineage.
                let in_flight = self.load_verified_bound_payout(&command)?;
                let committed_exact = committed_in_flight.encode()?;
                if in_flight.record.state != PayoutStateV1::InFlight
                    || in_flight.snapshot.state_version()
                        != verified.snapshot.state_version().checked_add(1).ok_or(
                            PayoutOutboxWorkerErrorV1::StoreInvariant(
                                "payout state version overflows",
                            ),
                        )?
                    || in_flight.snapshot.updated_at() != updated_at
                    || in_flight.record.exact_latest_status_response.as_deref()
                        != Some(committed_exact.as_slice())
                {
                    return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                        "signed InFlight successor is not the committed worker transition",
                    ));
                }
                let outcome = self
                    .executor
                    .submit_once(&command, execution_context)
                    .conservative_outcome();
                self.finish_external_outcome(clock, &command, outcome)
            }
            PayoutStateV1::InFlight => {
                let outcome = self
                    .executor
                    .reconcile(&command, execution_context)
                    .conservative_outcome();
                self.finish_external_outcome(clock, &command, outcome)
            }
            PayoutStateV1::Succeeded | PayoutStateV1::Failed => {
                Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                    "terminal payout retained a claimable outbox command",
                ))
            }
        }
    }

    fn finish_external_outcome(
        &mut self,
        clock: &mut impl PayoutWorkerClockV1,
        command: &ExternalPayoutCommandV1,
        outcome: ExternalPayoutOutcomeV1,
    ) -> Result<PayoutOutboxWorkerProgressV1, PayoutOutboxWorkerErrorV1> {
        if outcome == ExternalPayoutOutcomeV1::OutcomeUnknown {
            return Ok(PayoutOutboxWorkerProgressV1::OutcomeUnknown {
                payout_id: command.payout_id,
            });
        }
        let verified = self.load_verified_bound_payout(command)?;
        let record = &verified.record;
        if matches!(
            record.state,
            PayoutStateV1::Succeeded | PayoutStateV1::Failed
        ) {
            let matches_outcome = matches!(
                (record.state, outcome),
                (PayoutStateV1::Succeeded, ExternalPayoutOutcomeV1::Succeeded)
                    | (
                        PayoutStateV1::Failed,
                        ExternalPayoutOutcomeV1::DefinitelyFailed
                    )
            );
            if !matches_outcome {
                return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                    "terminal payout conflicts with external outcome",
                ));
            }
            return Ok(PayoutOutboxWorkerProgressV1::ConcurrentAdvance {
                payout_id: command.payout_id,
            });
        }
        if record.state != PayoutStateV1::InFlight {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "known external outcome has no InFlight payout",
            ));
        }
        let Some(updated_at) = monotonic_clock_value(clock, record.updated_at)? else {
            return Ok(PayoutOutboxWorkerProgressV1::TerminalCommitDeferred {
                payout_id: command.payout_id,
                outcome,
            });
        };
        let next_state = match outcome {
            ExternalPayoutOutcomeV1::Succeeded => PayoutStateV1::Succeeded,
            ExternalPayoutOutcomeV1::DefinitelyFailed => PayoutStateV1::Failed,
            ExternalPayoutOutcomeV1::OutcomeUnknown => unreachable!("handled above"),
        };
        if self
            .advance_status(&verified, command, next_state, updated_at)?
            .is_none()
        {
            // A failed predecessor CAS is not itself evidence that the
            // external outcome remains unresolved. Reload the signed durable
            // winner before deciding whether reconciliation is still needed.
            // This also prevents a matching terminal winner from being left
            // behind a completed (therefore no longer claimable) outbox row.
            let winner = self.load_verified_bound_payout(command)?;
            return match (winner.record.state, outcome) {
                (PayoutStateV1::Succeeded, ExternalPayoutOutcomeV1::Succeeded)
                | (PayoutStateV1::Failed, ExternalPayoutOutcomeV1::DefinitelyFailed) => {
                    Ok(PayoutOutboxWorkerProgressV1::ConcurrentAdvance {
                        payout_id: command.payout_id,
                    })
                }
                (PayoutStateV1::Succeeded | PayoutStateV1::Failed, _) => {
                    Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                        "terminal payout winner conflicts with external outcome",
                    ))
                }
                (PayoutStateV1::InFlight, _) => {
                    Ok(PayoutOutboxWorkerProgressV1::TerminalCommitRaced {
                        payout_id: command.payout_id,
                        outcome,
                    })
                }
                (PayoutStateV1::Accepted, _) => Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                    "terminal payout CAS winner rolled state back to Accepted",
                )),
            };
        }
        Ok(match next_state {
            PayoutStateV1::Succeeded => PayoutOutboxWorkerProgressV1::Succeeded {
                payout_id: command.payout_id,
            },
            PayoutStateV1::Failed => PayoutOutboxWorkerProgressV1::Failed {
                payout_id: command.payout_id,
            },
            PayoutStateV1::Accepted | PayoutStateV1::InFlight => {
                unreachable!("terminal outcome selected above")
            }
        })
    }

    fn load_verified_bound_payout(
        &self,
        command: &ExternalPayoutCommandV1,
    ) -> Result<VerifiedBoundPayoutV1, PayoutOutboxWorkerErrorV1> {
        let identity = self.store.identity()?;
        let expected_command_id =
            issuer_payout_outbox_command_id_v1(&identity.issuer_id, &command.payout_id);
        if !constant_time_eq_32(&command.command_id, &expected_command_id) {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "outbox command id is not derived from issuer and payout",
            ));
        }
        let record = self.store.payout_by_id(&command.payout_id)?.ok_or(
            PayoutOutboxWorkerErrorV1::StoreInvariant("claimed payout row is missing"),
        )?;
        if record.payout_id != command.payout_id
            || record.payout_target_id != command.payout_target_id
            || record.unit != command.unit
            || record.payout_value != command.payout_value
        {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "outbox command does not match payout row",
            ));
        }

        let initial = IssuerPayoutResponseV1::decode(&record.exact_initial_response)?;
        if initial.encode()? != record.exact_initial_response {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "initial payout response is not canonical",
            ));
        }
        let latest = record
            .exact_latest_status_response
            .as_deref()
            .map(IssuerPayoutStatusResponseV1::decode)
            .transpose()?;
        if let (Some(response), Some(exact)) = (
            latest.as_ref(),
            record.exact_latest_status_response.as_ref(),
        ) {
            if response.encode()? != *exact {
                return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                    "latest payout status response is not canonical",
                ));
            }
        }

        let current_verifying_key = self.issuer_settlement_signing_key.verifying_key();
        let keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &identity.issuer_id,
            current_key: &current_verifying_key,
            retained_keys: self.retained_issuer_settlement_keys,
        };
        let snapshot = verify_persisted_payout_snapshot_from_store_record_v1(
            &record.request_digest,
            &initial,
            latest.as_ref(),
            &keyring,
        )?;
        if initial.request_digest != record.request_digest
            || initial.issuer_id != identity.issuer_id
            || initial.provider_id != record.provider_id
            || initial.account_id != record.account_id
            || initial.payout_target_id != record.payout_target_id
            || initial.payout_intent_id != record.payout_intent_id
            || initial.payout_id != record.payout_id
            || initial.unit != record.unit
            || initial.payout_value != record.payout_value
            || initial.total_debit != record.total_debit
            || initial.state != PayoutStateV1::Accepted
            || initial.state_version != 1
            || initial.ledger_transaction_id != record.ledger_transaction_id
            || snapshot.payout_id() != &record.payout_id
            || snapshot.payout_request_digest() != &record.request_digest
            || snapshot.ledger_transaction_id() != &record.ledger_transaction_id
            || snapshot.state() != record.state
            || snapshot.state_version() != record.state_version
            || snapshot.updated_at() != record.updated_at
        {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "signed payout snapshots do not match durable row",
            ));
        }
        Ok(VerifiedBoundPayoutV1 { record, snapshot })
    }

    fn advance_status(
        &self,
        verified: &VerifiedBoundPayoutV1,
        command: &ExternalPayoutCommandV1,
        next_state: PayoutStateV1,
        updated_at: u64,
    ) -> Result<Option<IssuerPayoutStatusResponseV1>, PayoutOutboxWorkerErrorV1> {
        let record = &verified.record;
        let identity = self.store.identity()?;
        let current_verifying_key = self.issuer_settlement_signing_key.verifying_key();
        if command.payout_id != record.payout_id {
            return Err(PayoutOutboxWorkerErrorV1::StoreInvariant(
                "payout command changed after signed row verification",
            ));
        }
        let next_version = verified.snapshot.state_version().checked_add(1).ok_or(
            PayoutOutboxWorkerErrorV1::StoreInvariant("payout state version overflows"),
        )?;
        let request_digest =
            worker_status_request_digest(&identity.issuer_id, command, next_state, next_version);
        let registration_digest =
            worker_status_registration_digest(&identity.issuer_id, &command.command_id);
        let candidate = IssuerPayoutStatusResponseV1 {
            issuer_settlement_key_id: [0; 16],
            request_digest,
            registration_digest,
            issuer_id: identity.issuer_id,
            provider_id: record.provider_id,
            account_id: record.account_id,
            payout_id: record.payout_id,
            payout_request_digest: record.request_digest,
            payout_target_id: record.payout_target_id,
            unit: record.unit,
            payout_value: record.payout_value,
            total_debit: record.total_debit,
            state: next_state,
            ledger_transaction_id: record.ledger_transaction_id,
            state_version: next_version,
            updated_at,
            signature: [0; 64],
        };
        let mut committer = self.store.payout_status_committer(&current_verifying_key);
        match IssuerPayoutStatusResponseV1::sign_and_commit_successor(
            candidate,
            &verified.snapshot,
            self.issuer_settlement_signing_key,
            &mut committer,
        ) {
            Ok(signed) => Ok(Some(signed)),
            Err(PayoutCommitErrorV1::Conflict { .. }) => Ok(None),
            Err(PayoutCommitErrorV1::Protocol(error)) => Err(error.into()),
            Err(PayoutCommitErrorV1::Store(error)) => Err(error.into()),
        }
    }
}

fn next_clock_value(
    clock: &mut impl PayoutWorkerClockV1,
) -> Result<u64, PayoutOutboxWorkerErrorV1> {
    clock
        .now_unix()
        .filter(|value| *value != 0)
        .ok_or(PayoutOutboxWorkerErrorV1::ClockUnavailable)
}

fn monotonic_clock_value(
    clock: &mut impl PayoutWorkerClockV1,
    previous: u64,
) -> Result<Option<u64>, PayoutOutboxWorkerErrorV1> {
    Ok(Some(next_clock_value(clock)?).filter(|value| *value > previous))
}

fn worker_status_request_digest(
    issuer_id: &[u8; 32],
    command: &ExternalPayoutCommandV1,
    next_state: PayoutStateV1,
    next_version: u64,
) -> [u8; 32] {
    hash_parts(
        WORKER_STATUS_REQUEST_DIGEST_DOMAIN_V1,
        &[
            issuer_id,
            &command.command_id,
            &command.payout_id,
            &[next_state as u8],
            &next_version.to_le_bytes(),
        ],
    )
}

fn worker_status_registration_digest(issuer_id: &[u8; 32], command_id: &[u8; 32]) -> [u8; 32] {
    hash_parts(
        WORKER_STATUS_REGISTRATION_DIGEST_DOMAIN_V1,
        &[issuer_id, command_id],
    )
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn constant_time_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}
