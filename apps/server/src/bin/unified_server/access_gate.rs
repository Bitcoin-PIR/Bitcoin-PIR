//! Access gate (docs/CREDITS.md "Access policy"): decides, per metered
//! frame, whether it is served free, charged to the connection's credits, or
//! served free on the backend's best-effort lane — and refuses it otherwise.
//!
//! The policy is the operator's (`--require-credits`, `--access
//! BACKEND=MODE`, `--free-threads`, `--free-queue-wait-ms`) and is published
//! in `GET_INFO_JSON` so clients know what to expect from this server.
//!
//! A best-effort lane is lower priority by construction: a connection whose
//! credits cover the frame is charged and served at once; a free frame needs
//! one of the lane's `free_concurrency` slots (FIFO queue, bounded wait and
//! length), stays within the optional hourly free budget, and its heavy work
//! runs on a small shared thread pool at nice 10, so paid work keeps every
//! other core and wins the scheduler when both run.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pir_credit::{Access, AccessPolicy, Backend, MeteredOp, FREE_LANE_BUSY_PREFIX};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::credit_gate::GasBalanceV1;

/// How long a free frame may wait for a slot before it is refused as busy.
pub(crate) const DEFAULT_FREE_QUEUE_WAIT: Duration = Duration::from_secs(10);
/// Threads in the shared low-priority pool that runs free frames' work.
pub(crate) const DEFAULT_FREE_THREADS: usize = 1;
/// Free frames that may wait per slot before new ones are refused outright.
const QUEUE_PER_SLOT: usize = 8;
/// Nice value of the free-lane threads (Linux).
const FREE_LANE_NICE: i32 = 10;

/// What the gate decided for one frame.
pub(crate) enum Admission {
    /// Unmetered, or the backend is free here: no charge, normal priority.
    Free,
    /// Charged to the connection's balance: normal priority.
    Charged,
    /// Served free on the best-effort lane; hold the ticket for the frame.
    FreeLane(FreeLaneTicket),
    /// Refused; nothing charged. The message goes back as `RESP_ERROR`.
    Refused(String),
}

/// A slot on a best-effort lane, held while the frame runs.
pub(crate) struct FreeLaneTicket {
    lane: Arc<FreeLane>,
    pool: Arc<rayon::ThreadPool>,
    _permit: OwnedSemaphorePermit,
}

impl FreeLaneTicket {
    /// The low-priority pool the frame's heavy work runs on.
    pub(crate) fn pool(&self) -> Arc<rayon::ThreadPool> {
        Arc::clone(&self.pool)
    }

    /// Account the response's egress against the free budget and release
    /// the slot.
    pub(crate) fn finish(self, egress_gas: u64) {
        self.lane.free_gas.fetch_add(egress_gas, Ordering::Relaxed);
        if let Some(budget) = &self.lane.budget {
            budget.lock().unwrap().spend(egress_gas, Instant::now());
        }
    }
}

/// Continuous-refill budget of free gas per hour.
#[derive(Debug)]
struct GasBudget {
    per_hour: f64,
    tokens: f64,
    refilled: Instant,
}

impl GasBudget {
    fn new(per_hour: u64, now: Instant) -> Self {
        Self {
            per_hour: per_hour as f64,
            tokens: per_hour as f64,
            refilled: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.per_hour / 3600.0).min(self.per_hour);
        self.refilled = now;
    }

    /// Take `gas` if the budget has it.
    fn try_take(&mut self, gas: u64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= gas as f64 {
            self.tokens -= gas as f64;
            true
        } else {
            false
        }
    }

    /// Give back gas taken for a frame that was refused after all.
    fn refund(&mut self, gas: u64) {
        self.tokens = (self.tokens + gas as f64).min(self.per_hour);
    }

    /// Spend gas known only afterwards (egress); may run the budget into
    /// deficit, which the refill then pays off.
    fn spend(&mut self, gas: u64, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - gas as f64).max(-self.per_hour);
    }
}

/// One backend's best-effort lane.
struct FreeLane {
    backend: Backend,
    concurrency: u32,
    permits: Arc<Semaphore>,
    waiting: AtomicUsize,
    max_waiting: usize,
    budget: Option<Mutex<GasBudget>>,
    per_hour: Option<u64>,
    served: AtomicU64,
    busy: AtomicU64,
    free_gas: AtomicU64,
}

impl FreeLane {
    fn new(backend: Backend, concurrency: u32, per_hour: Option<u64>, now: Instant) -> Self {
        Self {
            backend,
            concurrency,
            permits: Arc::new(Semaphore::new(concurrency as usize)),
            waiting: AtomicUsize::new(0),
            max_waiting: concurrency as usize * QUEUE_PER_SLOT,
            budget: per_hour.map(|g| Mutex::new(GasBudget::new(g, now))),
            per_hour,
            served: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            free_gas: AtomicU64::new(0),
        }
    }
}

/// Decrements the waiting count however the wait ends.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The server's policy plus the state of its best-effort lanes.
pub(crate) struct AccessGateV1 {
    policy: AccessPolicy,
    /// Whether this server takes credit presentations (an issuer is set).
    can_pay: bool,
    lanes: [Option<Arc<FreeLane>>; 4],
    pool: Option<Arc<rayon::ThreadPool>>,
    free_threads: usize,
    queue_wait: Duration,
    report_started: Mutex<Instant>,
}

impl fmt::Debug for AccessGateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessGateV1")
            .field("policy", &self.policy)
            .field("can_pay", &self.can_pay)
            .finish()
    }
}

fn lane_index(backend: Backend) -> usize {
    match backend {
        Backend::Dpf => 0,
        Backend::Harmony => 1,
        Backend::Onion => 2,
        Backend::Oram => 3,
    }
}

fn lower_thread_priority() {
    #[cfg(target_os = "linux")]
    // SAFETY: setpriority(PRIO_PROCESS, 0, n) only changes the calling
    // thread's nice value on Linux; raising it needs no privilege.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, FREE_LANE_NICE);
    }
}

impl AccessGateV1 {
    /// Build the gate. `can_pay` is whether credits are enabled (an issuer
    /// is configured); a paid backend needs it.
    pub(crate) fn new(
        policy: AccessPolicy,
        can_pay: bool,
        free_threads: usize,
        queue_wait: Duration,
    ) -> Result<Self, String> {
        let paid: Vec<&str> = Backend::ALL
            .into_iter()
            .filter(|b| matches!(policy.get(*b), Access::Paid))
            .map(Backend::name)
            .collect();
        if !paid.is_empty() && !can_pay {
            return Err(format!(
                "paid access ({}) needs --credit-issuer-url: without an issuer no client can pay",
                paid.join(", ")
            ));
        }
        if free_threads == 0 {
            return Err("--free-threads must be at least 1".to_owned());
        }
        let now = Instant::now();
        let lanes = Backend::ALL.map(|backend| match policy.get(backend) {
            Access::BestEffort {
                free_concurrency,
                free_gas_per_hour,
            } => Some(Arc::new(FreeLane::new(
                backend,
                free_concurrency,
                free_gas_per_hour,
                now,
            ))),
            Access::Free | Access::Paid => None,
        });
        let pool = if lanes.iter().any(Option::is_some) {
            Some(Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(free_threads)
                    .thread_name(|i| format!("free-lane-{i}"))
                    .start_handler(|_| lower_thread_priority())
                    .build()
                    .map_err(|e| format!("free-lane thread pool: {e}"))?,
            ))
        } else {
            None
        };
        Ok(Self {
            policy,
            can_pay,
            lanes,
            pool,
            free_threads,
            queue_wait,
            report_started: Mutex::new(now),
        })
    }

    pub(crate) fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    pub(crate) fn queue_wait(&self) -> Duration {
        self.queue_wait
    }

    /// Startup log lines.
    pub(crate) fn startup_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Access: {}", self.policy)];
        if self.pool.is_some() {
            lines.push(format!(
                "Access: best-effort free lanes run on {} low-priority thread(s) (nice {FREE_LANE_NICE}); a free frame waits at most {}s for a slot; paid frames go first{}",
                self.free_threads,
                self.queue_wait.as_secs(),
                if self.can_pay { "" } else { " (no issuer: nobody can pay, so the lanes are the only way in)" }
            ));
        }
        lines
    }

    fn busy_message(&self, lane: &FreeLane, reason: &str) -> String {
        let advice = if self.can_pay {
            "present credits for priority or retry later"
        } else {
            "retry later"
        };
        format!(
            "{FREE_LANE_BUSY_PREFIX}: {} {reason}; {advice}",
            lane.backend
        )
    }

    /// Decide one frame. `op` is the frame's metered kind and `cost` its
    /// admission gas (work plus base fee); `None` means unmetered here.
    pub(crate) async fn admit(
        &self,
        op: Option<(MeteredOp, u8)>,
        cost: Option<u64>,
        balance: &mut GasBalanceV1,
    ) -> Admission {
        let (Some((op, _)), Some(cost)) = (op, cost) else {
            return Admission::Free;
        };
        let (backend, access) = self.policy.for_op(op);
        match access {
            Access::Free => Admission::Free,
            Access::Paid => match balance.admit(cost) {
                Ok(_) => Admission::Charged,
                Err(refusal) => Admission::Refused(refusal.to_string()),
            },
            Access::BestEffort { .. } => {
                if balance.covers(cost) {
                    return match balance.admit(cost) {
                        Ok(_) => Admission::Charged,
                        Err(refusal) => Admission::Refused(refusal.to_string()),
                    };
                }
                let lane = self.lanes[lane_index(backend)]
                    .as_ref()
                    .expect("a best-effort backend has a lane");
                self.enter_lane(lane, cost).await
            }
        }
    }

    async fn enter_lane(&self, lane: &Arc<FreeLane>, cost: u64) -> Admission {
        let now = Instant::now();
        if let Some(budget) = &lane.budget {
            if !budget.lock().unwrap().try_take(cost, now) {
                lane.busy.fetch_add(1, Ordering::Relaxed);
                let per_hour = lane.per_hour.unwrap_or_default();
                return Admission::Refused(self.busy_message(
                    lane,
                    &format!("has used its free budget of {per_hour} gas per hour"),
                ));
            }
        }
        let refund = |lane: &FreeLane| {
            if let Some(budget) = &lane.budget {
                budget.lock().unwrap().refund(cost);
            }
            lane.busy.fetch_add(1, Ordering::Relaxed);
        };
        let queued = lane.waiting.fetch_add(1, Ordering::Relaxed) + 1;
        let _waiting = Waiting(&lane.waiting);
        if queued > lane.max_waiting {
            refund(lane);
            return Admission::Refused(self.busy_message(
                lane,
                &format!("has {} free frame(s) queued already", lane.max_waiting),
            ));
        }
        let permit =
            match tokio::time::timeout(self.queue_wait, Arc::clone(&lane.permits).acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) | Err(_) => {
                    refund(lane);
                    return Admission::Refused(self.busy_message(
                        lane,
                        &format!(
                            "serves {} free frame(s) at a time and none was free within {}s",
                            lane.concurrency,
                            self.queue_wait.as_secs()
                        ),
                    ));
                }
            };
        lane.served.fetch_add(1, Ordering::Relaxed);
        lane.free_gas.fetch_add(cost, Ordering::Relaxed);
        Admission::FreeLane(FreeLaneTicket {
            lane: Arc::clone(lane),
            pool: Arc::clone(self.pool.as_ref().expect("lanes come with a pool")),
            _permit: permit,
        })
    }

    /// Hourly lines, one per best-effort lane, when the interval has passed.
    pub(crate) fn due_lines(&self, now: Instant, interval: Duration) -> Option<Vec<String>> {
        let mut started = self.report_started.lock().unwrap();
        if now.saturating_duration_since(*started) < interval {
            return None;
        }
        *started = now;
        let secs = interval.as_secs();
        Some(
            self.lanes
                .iter()
                .flatten()
                .map(|lane| {
                    format!(
                        "[access {}] last {secs}s: free_served={} free_gas={} busy={}",
                        lane.backend,
                        lane.served.swap(0, Ordering::Relaxed),
                        lane.free_gas.swap(0, Ordering::Relaxed),
                        lane.busy.swap(0, Ordering::Relaxed),
                    )
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BE1: Access = Access::BestEffort {
        free_concurrency: 1,
        free_gas_per_hour: None,
    };

    fn gate(policy: AccessPolicy, can_pay: bool) -> AccessGateV1 {
        AccessGateV1::new(policy, can_pay, 1, Duration::from_millis(50)).unwrap()
    }

    fn dpf() -> Option<(MeteredOp, u8)> {
        Some((MeteredOp::DpfIndexRound, 0))
    }

    fn policy(entries: &[(Backend, Access)], default: Access) -> AccessPolicy {
        let mut p = AccessPolicy::uniform(default);
        for (b, a) in entries {
            p.set(*b, *a);
        }
        p
    }

    #[tokio::test]
    async fn free_and_unmetered_frames_are_never_charged() {
        let g = gate(AccessPolicy::uniform(Access::Free), false);
        let mut balance = GasBalanceV1::new();
        assert!(matches!(
            g.admit(dpf(), Some(1_400), &mut balance).await,
            Admission::Free
        ));
        assert!(matches!(
            g.admit(None, None, &mut balance).await,
            Admission::Free
        ));
        // A backend this database does not serve prices at None: let it through.
        let g = gate(AccessPolicy::uniform(Access::Paid), true);
        assert!(matches!(
            g.admit(dpf(), None, &mut balance).await,
            Admission::Free
        ));
        assert_eq!(balance.gas(), 0);
    }

    #[tokio::test]
    async fn paid_frames_are_charged_or_refused_with_the_gas_numbers() {
        let g = gate(AccessPolicy::uniform(Access::Paid), true);
        let mut balance = GasBalanceV1::new();
        match g.admit(dpf(), Some(1_400), &mut balance).await {
            Admission::Refused(message) => assert!(
                message.starts_with("insufficient gas: this frame needs 1400"),
                "{message}"
            ),
            _ => panic!("expected a refusal"),
        }
        balance.top_up(2_000);
        assert!(matches!(
            g.admit(dpf(), Some(1_400), &mut balance).await,
            Admission::Charged
        ));
        assert_eq!(balance.gas(), 600);
    }

    #[tokio::test]
    async fn best_effort_charges_a_covered_frame_and_lanes_an_uncovered_one() {
        let g = gate(policy(&[(Backend::Dpf, BE1)], Access::Paid), true);
        let mut paying = GasBalanceV1::new();
        paying.top_up(10_000);
        assert!(matches!(
            g.admit(dpf(), Some(1_400), &mut paying).await,
            Admission::Charged
        ));
        assert_eq!(paying.gas(), 8_600);

        let mut broke = GasBalanceV1::new();
        broke.top_up(100);
        let ticket = match g.admit(dpf(), Some(1_400), &mut broke).await {
            Admission::FreeLane(ticket) => ticket,
            _ => panic!("expected the free lane"),
        };
        assert_eq!(broke.gas(), 100, "the free lane leaves the balance alone");

        // The only slot is taken: the next free frame waits, then is refused
        // as busy — while a paying connection still goes straight through.
        let mut other = GasBalanceV1::new();
        match g.admit(dpf(), Some(1_400), &mut other).await {
            Admission::Refused(message) => {
                assert!(pir_credit::is_free_lane_busy(&message), "{message}");
                assert!(
                    message.contains("serves 1 free frame(s) at a time"),
                    "{message}"
                );
                assert!(
                    message.ends_with("present credits for priority or retry later"),
                    "{message}"
                );
            }
            _ => panic!("expected busy"),
        }
        assert!(matches!(
            g.admit(dpf(), Some(1_400), &mut paying).await,
            Admission::Charged
        ));

        // Releasing the slot lets the next free frame in.
        ticket.finish(500);
        assert!(matches!(
            g.admit(dpf(), Some(1_400), &mut other).await,
            Admission::FreeLane(_)
        ));
    }

    #[tokio::test]
    async fn a_waiting_free_frame_gets_the_slot_when_it_frees_up() {
        let g = Arc::new(
            AccessGateV1::new(
                policy(&[(Backend::Oram, BE1)], Access::Paid),
                true,
                1,
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let oram = Some((MeteredOp::OramLookup, 0));
        let mut a = GasBalanceV1::new();
        let first = match g.admit(oram, Some(100), &mut a).await {
            Admission::FreeLane(t) => t,
            _ => panic!("first frame gets the slot"),
        };
        let waiter = {
            let g = Arc::clone(&g);
            tokio::spawn(async move {
                let mut b = GasBalanceV1::new();
                matches!(
                    g.admit(oram, Some(100), &mut b).await,
                    Admission::FreeLane(_)
                )
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.finish(0);
        assert!(
            waiter.await.unwrap(),
            "the queued frame is served once the slot frees"
        );
    }

    #[tokio::test]
    async fn an_hourly_budget_stops_the_lane_once_spent() {
        let be = Access::BestEffort {
            free_concurrency: 4,
            free_gas_per_hour: Some(3_000),
        };
        let g = gate(policy(&[(Backend::Dpf, be)], Access::Paid), true);
        let mut b = GasBalanceV1::new();
        let t1 = match g.admit(dpf(), Some(1_400), &mut b).await {
            Admission::FreeLane(t) => t,
            _ => panic!(),
        };
        t1.finish(1_000); // egress spends from the budget too
        match g.admit(dpf(), Some(1_400), &mut b).await {
            Admission::Refused(message) => {
                assert!(
                    message.contains("has used its free budget of 3000 gas per hour"),
                    "{message}"
                )
            }
            _ => panic!("expected the budget refusal"),
        }
    }

    #[tokio::test]
    async fn tree_tops_ride_the_more_open_bucket_backend() {
        let g = gate(
            policy(&[(Backend::Harmony, Access::Free)], Access::Paid),
            true,
        );
        let mut b = GasBalanceV1::new();
        assert!(matches!(
            g.admit(Some((MeteredOp::TreeTops, 0)), Some(25), &mut b)
                .await,
            Admission::Free
        ));
        assert!(matches!(
            g.admit(dpf(), Some(1_400), &mut b).await,
            Admission::Refused(_)
        ));
    }

    #[test]
    fn paid_access_needs_an_issuer_and_busy_advice_follows_it() {
        assert!(AccessGateV1::new(
            AccessPolicy::uniform(Access::Paid),
            false,
            1,
            DEFAULT_FREE_QUEUE_WAIT
        )
        .is_err());
        assert!(
            AccessGateV1::new(AccessPolicy::uniform(BE1), true, 0, DEFAULT_FREE_QUEUE_WAIT)
                .is_err()
        );
        let g = gate(AccessPolicy::uniform(BE1), false);
        let lane = g.lanes[0].as_ref().unwrap();
        assert!(g.busy_message(lane, "x").ends_with("; retry later"));
        assert_eq!(
            g.startup_lines()[0],
            "Access: dpf=best-effort:1 harmony=best-effort:1 onion=best-effort:1 oram=best-effort:1"
        );
    }

    #[tokio::test]
    async fn hourly_lines_report_and_reset_each_lane() {
        let g = gate(policy(&[(Backend::Dpf, BE1)], Access::Paid), true);
        let mut b = GasBalanceV1::new();
        if let Admission::FreeLane(t) = g.admit(dpf(), Some(1_400), &mut b).await {
            t.finish(600);
        }
        let now = Instant::now() + Duration::from_secs(3_600);
        let lines = g.due_lines(now, Duration::from_secs(3_600)).unwrap();
        assert_eq!(
            lines,
            vec!["[access dpf] last 3600s: free_served=1 free_gas=2000 busy=0".to_owned()]
        );
        assert!(g.due_lines(now, Duration::from_secs(3_600)).is_none());
    }

    #[test]
    fn budget_refills_continuously_and_caps_at_one_hour() {
        let t0 = Instant::now();
        let mut budget = GasBudget::new(3_600, t0);
        assert!(budget.try_take(3_600, t0));
        assert!(!budget.try_take(1, t0));
        assert!(budget.try_take(10, t0 + Duration::from_secs(10)));
        budget.spend(10_000, t0 + Duration::from_secs(10));
        assert!(budget.tokens >= -3_600.0);
        budget.refill(t0 + Duration::from_secs(100_000));
        assert_eq!(budget.tokens, 3_600.0);
    }
}
