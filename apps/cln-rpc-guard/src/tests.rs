use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const PAYEE: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn label() -> String {
    format!("bpir-v1-{}", "ab".repeat(32))
}

fn valid_request(method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#)
}

fn valid_invoice_request() -> String {
    valid_request(
        "invoice",
        &format!(
            r#"{{"amount_msat":44000,"label":"{}","description":"{}","expiry":600,"exposeprivatechannels":false,"deschashonly":true}}"#,
            label(),
            ANONYMOUS_DESCRIPTION_V1
        ),
    )
}

#[derive(Default)]
struct ScriptedUpstreamV1 {
    requests: Mutex<Vec<Vec<u8>>>,
    response: Mutex<Option<Result<Vec<u8>, ()>>>,
}

impl ScriptedUpstreamV1 {
    fn with_response(response: impl Into<Vec<u8>>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(Ok(response.into()))),
        }
    }

    fn failing() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(Err(()))),
        }
    }
}

impl GuardUpstreamV1 for ScriptedUpstreamV1 {
    fn call(&self, request: &[u8], deadline: std::time::Instant) -> Result<Zeroizing<Vec<u8>>, ()> {
        if std::time::Instant::now() >= deadline {
            return Err(());
        }
        self.requests.lock().unwrap().push(request.to_vec());
        self.response
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Err(()))
            .map(Zeroizing::new)
    }
}

async fn invoke(request: &[u8], upstream: Arc<ScriptedUpstreamV1>) -> Vec<u8> {
    invoke_with_policy(request, upstream, test_runtime_policy()).await
}

async fn invoke_with_policy(
    request: &[u8],
    upstream: Arc<ScriptedUpstreamV1>,
    runtime_policy: Arc<GuardRuntimePolicyV1>,
) -> Vec<u8> {
    let (mut client, server) = UnixStream::pair().unwrap();
    let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    let task = tokio::spawn(async move {
        serve_connection(
            server,
            upstream,
            runtime_policy,
            permit,
            Duration::from_millis(250),
        )
        .await;
    });
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut output = Vec::new();
    client.read_to_end(&mut output).await.unwrap();
    task.await.unwrap();
    output
}

fn test_runtime_policy() -> Arc<GuardRuntimePolicyV1> {
    Arc::new(GuardRuntimePolicyV1 {
        max_invoice_msat: 100_000_000,
        invoice_admission: InvoiceAdmissionV1::new(100, 100, 10_000, std::time::Instant::now())
            .unwrap(),
    })
}

fn validate_test_request(bytes: &[u8]) -> Result<ValidatedRequestV1, ()> {
    validate_request(bytes, 100_000_000)
}

#[test]
fn request_surface_is_closed_world_and_reencoded() {
    let getinfo = validate_test_request(valid_request("getinfo", "{}").as_bytes()).unwrap();
    assert!(matches!(getinfo.method, AllowedMethodV1::GetInfo));
    assert_eq!(
        getinfo.canonical.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}}

"#
    );

    let list = validate_test_request(
        valid_request("listinvoices", &format!(r#"{{"label":"{}"}}"#, label())).as_bytes(),
    )
    .unwrap();
    assert!(matches!(list.method, AllowedMethodV1::ListInvoices));
    assert_eq!(
        list.expected_label.as_ref().map(|label| label.as_str()),
        Some(label().as_str())
    );

    let invoice = validate_test_request(valid_invoice_request().as_bytes()).unwrap();
    assert!(matches!(invoice.method, AllowedMethodV1::Invoice));
    assert_eq!(
        invoice.expected_label.as_ref().map(|label| label.as_str()),
        Some(label().as_str())
    );
}

#[test]
fn batch_notification_unknown_duplicate_and_smuggled_fields_fail_closed() {
    let cases = [
        r#"[{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}}]"#.to_owned(),
        r#"{"jsonrpc":"2.0","method":"getinfo","params":{}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"id":1,"method":"getinfo","params":{}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"method":"getinfo","method":"getinfo","params":{}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{},"extra":1}"#.to_owned(),
        valid_request("getinfo", r#"{"extra":1}"#),
        valid_request("getinfo", r#"{"extra":1,"extra":1}"#),
        valid_request("pay", "{}"),
        r#"{"jsonrpc":"2.0","id":null,"method":"getinfo","params":{}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}} {}"#.to_owned(),
    ];
    for case in cases {
        assert!(
            validate_test_request(case.as_bytes()).is_err(),
            "accepted {case}"
        );
    }
}

#[test]
fn invoice_amount_label_expiry_description_and_flags_are_bounded() {
    let good = valid_invoice_request();
    let cases = [
        good.replace("44000", "0"),
        good.replace("44000", &(MAX_BITCOIN_MSAT_V1 + 1).to_string()),
        good.replace(&label(), "bpir-v1-deadbeef"),
        good.replace("\"expiry\":600", "\"expiry\":0"),
        good.replace(
            "\"expiry\":600",
            &format!("\"expiry\":{}", MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1 + 1),
        ),
        good.replace(ANONYMOUS_DESCRIPTION_V1, "query address 1abc"),
        good.replace(
            "\"exposeprivatechannels\":false",
            "\"exposeprivatechannels\":true",
        ),
        good.replace("\"deschashonly\":true", "\"deschashonly\":false"),
        good.replace(
            "\"deschashonly\":true",
            "\"deschashonly\":true,\"preimage\":\"00\"",
        ),
        good.replace(
            "\"amount_msat\":44000",
            "\"amount_msat\":44000,\"amount_msat\":44000",
        ),
        good.replace(
            &format!("\"label\":\"{}\"", label()),
            &format!("\"label\":\"{}\",\"label\":\"{}\"", label(), label()),
        ),
    ];
    for case in cases {
        assert!(
            validate_test_request(case.as_bytes()).is_err(),
            "accepted {case}"
        );
    }
    assert!(validate_request(good.as_bytes(), 43_999).is_err());
    assert!(validate_request(good.as_bytes(), 44_000).is_ok());
}

#[test]
fn invoice_rate_burst_runtime_cap_and_concurrency_are_atomic() {
    let started = std::time::Instant::now();
    let admission = InvoiceAdmissionV1::new(2, 2, 3, started).unwrap();
    assert!(admission.try_admit_at(started));
    assert!(admission.try_admit_at(started));
    assert!(!admission.try_admit_at(started));
    assert!(admission.try_admit_at(started + Duration::from_secs(30)));
    assert!(!admission.try_admit_at(started + Duration::from_secs(60)));

    let concurrent = Arc::new(InvoiceAdmissionV1::new(100, 100, 5, started).unwrap());
    let admitted = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for _ in 0..32 {
            let concurrent = concurrent.clone();
            let admitted = admitted.clone();
            scope.spawn(move || {
                if concurrent.try_admit_at(started) {
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(admitted.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn exhausted_invoice_budget_and_amount_ceiling_never_reach_cln() {
    let response = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"bolt11":"lnbc1abc","payment_hash":"{HASH}","expires_at":1700000600}}}}"#
    );
    let upstream = Arc::new(ScriptedUpstreamV1::with_response(response));
    let policy = Arc::new(GuardRuntimePolicyV1 {
        max_invoice_msat: 44_000,
        invoice_admission: InvoiceAdmissionV1::new(1, 1, 1, std::time::Instant::now()).unwrap(),
    });
    let framed = format!("{}\n\n", valid_invoice_request());
    assert!(
        !invoke_with_policy(framed.as_bytes(), upstream.clone(), policy.clone())
            .await
            .is_empty()
    );
    assert!(
        invoke_with_policy(framed.as_bytes(), upstream.clone(), policy)
            .await
            .is_empty()
    );
    assert_eq!(upstream.requests.lock().unwrap().len(), 1);

    let over_ceiling = Arc::new(GuardRuntimePolicyV1 {
        max_invoice_msat: 43_999,
        invoice_admission: InvoiceAdmissionV1::new(1, 1, 1, std::time::Instant::now()).unwrap(),
    });
    assert!(
        invoke_with_policy(framed.as_bytes(), upstream.clone(), over_ceiling)
            .await
            .is_empty()
    );
    assert_eq!(upstream.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn valid_request_reaches_upstream_and_secret_response_fields_are_removed() {
    let response = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"invoices":[{{"label":"{}","payment_hash":"{}","status":"paid","expires_at":1700000600,"bolt11":"lnbc1abc","amount_msat":"44000msat","amount_received_msat":"44001msat","paid_at":1700000010,"payment_preimage":"{}","description":"sensitive"}}],"warning":"ignored"}}}}"#,
        label(),
        HASH,
        "cc".repeat(32)
    );
    let upstream = Arc::new(ScriptedUpstreamV1::with_response(response));
    let framed = format!(
        "{}\n\n",
        valid_request("listinvoices", &format!(r#"{{"label":"{}"}}"#, label()))
    );
    let output = invoke(framed.as_bytes(), upstream.clone()).await;
    assert!(output.ends_with(b"\n\n"));
    assert!(!output
        .windows(b"payment_preimage".len())
        .any(|part| part == b"payment_preimage"));
    assert!(!output
        .windows(b"sensitive".len())
        .any(|part| part == b"sensitive"));
    let request = upstream.requests.lock().unwrap()[0].clone();
    assert!(request.ends_with(b"\n\n"));
    let parsed: serde_json::Value = serde_json::from_slice(&request[..request.len() - 2]).unwrap();
    assert_eq!(parsed["method"], "listinvoices");
    assert_eq!(parsed["params"]["label"], label());
}

#[tokio::test]
async fn remote_error_is_reduced_to_code_and_preserves_duplicate_label_recovery() {
    let upstream = Arc::new(ScriptedUpstreamV1::with_response(
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":900,"message":"duplicate label bpir-v1-secret","data":{"payment_preimage":"secret"}}}"#
            .to_vec(),
    ));
    let framed = format!("{}\n\n", valid_invoice_request());
    let output = invoke(framed.as_bytes(), upstream).await;
    assert_eq!(
        output,
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":900}}

"#
    );
}

#[tokio::test]
async fn invalid_request_and_upstream_failure_return_no_forged_response() {
    let forbidden = Arc::new(ScriptedUpstreamV1::with_response(Vec::new()));
    let output = invoke(
        br#"{"jsonrpc":"2.0","id":1,"method":"withdraw","params":{}}

"#,
        forbidden.clone(),
    )
    .await;
    assert!(output.is_empty());
    assert!(forbidden.requests.lock().unwrap().is_empty());

    let failing = Arc::new(ScriptedUpstreamV1::failing());
    let output = invoke(
        format!("{}\n\n", valid_request("getinfo", "{}")).as_bytes(),
        failing.clone(),
    )
    .await;
    assert!(output.is_empty());
    assert_eq!(failing.requests.lock().unwrap().len(), 1);
}

#[test]
fn response_identity_label_hash_status_and_shape_fail_closed() {
    let list = |label: &str, extra: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"invoices":[{{"label":"{label}","payment_hash":"{HASH}","status":"unpaid","expires_at":1700000600,"bolt11":"lnbc1abc","amount_msat":"44000msat"}}]{extra}}}}}"#
        )
    };
    assert!(sanitize_response(
        AllowedMethodV1::ListInvoices,
        Some(&label()),
        list(&label(), "").as_bytes()
    )
    .is_ok());
    for response in [
        list("bpir-v1-deadbeef", ""),
        list(&label(), r#", "invoices": []"#),
        list(&label(), r#", "unexpected": 1"#).replace(HASH, &HASH.to_uppercase()),
        r#"{"jsonrpc":"2.0","id":2,"result":{"invoices":[]}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"invoices":[]},"error":{"code":1}}"#.to_owned(),
    ] {
        assert!(sanitize_response(
            AllowedMethodV1::ListInvoices,
            Some(&label()),
            response.as_bytes()
        )
        .is_err());
    }
}

#[test]
fn getinfo_and_invoice_responses_are_bounded_and_reconstructed() {
    let getinfo = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"id":"{PAYEE}","network":"signet","version":"v24","fees_collected_msat":"secret"}}}}"#
    );
    let sanitized = sanitize_response(AllowedMethodV1::GetInfo, None, getinfo.as_bytes()).unwrap();
    assert_eq!(
        sanitized.as_slice(),
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"id":"{PAYEE}","network":"signet"}}}}"#)
            .as_bytes()
    );

    let invoice = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"bolt11":"lnbc1abc","payment_hash":"{HASH}","expires_at":1700000600,"payment_secret":"{}","warning":"ignored"}}}}"#,
        "cc".repeat(32)
    );
    let sanitized =
        sanitize_response(AllowedMethodV1::Invoice, Some(&label()), invoice.as_bytes()).unwrap();
    let text = std::str::from_utf8(&sanitized).unwrap();
    assert!(!text.contains("payment_secret"));
    assert!(!text.contains("warning"));
    assert!(text.contains("lnbc1abc"));

    let duplicate = getinfo.replace(
        &format!(r#""id":"{PAYEE}""#),
        &format!(r#""id":"{PAYEE}","id":"{PAYEE}""#),
    );
    assert!(sanitize_response(AllowedMethodV1::GetInfo, None, duplicate.as_bytes()).is_err());
}

#[test]
fn peer_identity_and_nonblocking_capacity_are_exact() {
    assert!(peer_identity_allowed(1001, 1002, 1001, 1002));
    assert!(!peer_identity_allowed(1001, 1003, 1001, 1002));
    assert!(!peer_identity_allowed(1004, 1002, 1001, 1002));

    let semaphore = Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().unwrap();
    assert!(semaphore.clone().try_acquire_owned().is_err());
    drop(permit);
    assert!(semaphore.try_acquire_owned().is_ok());
}

struct DelayedUpstreamV1 {
    calls: AtomicUsize,
    delay: Duration,
}

impl GuardUpstreamV1 for DelayedUpstreamV1 {
    fn call(
        &self,
        _request: &[u8],
        _deadline: std::time::Instant,
    ) -> Result<Zeroizing<Vec<u8>>, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        Err(())
    }
}

#[tokio::test]
async fn absolute_deadline_closes_client_but_retains_permit_until_blocking_call_finishes() {
    let upstream = Arc::new(DelayedUpstreamV1 {
        calls: AtomicUsize::new(0),
        delay: Duration::from_millis(150),
    });
    let semaphore = Arc::new(Semaphore::new(1));
    let permit = semaphore.clone().acquire_owned().await.unwrap();
    let runtime_policy = test_runtime_policy();
    let (mut client, server) = UnixStream::pair().unwrap();
    let upstream_for_task = upstream.clone();
    let task = tokio::spawn(async move {
        serve_connection(
            server,
            upstream_for_task,
            runtime_policy,
            permit,
            Duration::from_millis(40),
        )
        .await;
    });
    client
        .write_all(format!("{}\n\n", valid_request("getinfo", "{}")).as_bytes())
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut output = Vec::new();
    client.read_to_end(&mut output).await.unwrap();
    task.await.unwrap();
    assert!(output.is_empty());
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert!(semaphore.clone().try_acquire_owned().is_err());
    time::sleep(Duration::from_millis(140)).await;
    assert!(semaphore.try_acquire_owned().is_ok());
}

#[tokio::test]
async fn framing_rejects_suffix_oversize_and_timeout_without_calling_upstream() {
    let upstream = Arc::new(ScriptedUpstreamV1::with_response(Vec::new()));
    let suffix = format!("{}\n\n{{}}", valid_request("getinfo", "{}"));
    assert!(invoke(suffix.as_bytes(), upstream.clone()).await.is_empty());

    let mut oversize = vec![b' '; MAX_REQUEST_BYTES_V1 + 1];
    oversize.extend_from_slice(b"\n\n");
    assert!(invoke(&oversize, upstream.clone()).await.is_empty());
    assert!(upstream.requests.lock().unwrap().is_empty());

    let (mut client, server) = UnixStream::pair().unwrap();
    let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    let runtime_policy = test_runtime_policy();
    let upstream_for_task = upstream.clone();
    let task = tokio::spawn(async move {
        serve_connection(
            server,
            upstream_for_task,
            runtime_policy,
            permit,
            Duration::from_millis(30),
        )
        .await;
    });
    client.write_all(b"{").await.unwrap();
    time::sleep(Duration::from_millis(60)).await;
    let mut output = Vec::new();
    client.read_to_end(&mut output).await.unwrap();
    task.await.unwrap();
    assert!(output.is_empty());
    assert!(upstream.requests.lock().unwrap().is_empty());
}

fn current_ids() -> (u32, u32) {
    (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )
}

fn listener_config(path: PathBuf) -> GuardConfig {
    let (uid, gid) = current_ids();
    GuardConfig {
        listen_socket: path.clone(),
        upstream_socket: path.with_file_name("upstream-rpc"),
        guard_uid: uid,
        guard_gid: gid.wrapping_add(1),
        issuer_uid: uid.wrapping_add(1),
        issuer_gid: gid,
        upstream_expected_uid: uid,
        upstream_expected_gid: None,
        timeout: Duration::from_secs(1),
        max_in_flight: 2,
        max_invoice_msat: 100_000_000,
        max_invoices_per_minute: 10,
        max_invoice_burst: 2,
        max_invoices_per_runtime: 100,
    }
}

#[tokio::test]
async fn listener_path_is_hardened_and_replacement_is_detected_without_unlinking_attacker() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710)).unwrap();
    let config = listener_config(directory.path().join("issuer-rpc"));
    let (listener, guard) = create_listener(&config).unwrap();
    guard.validate().unwrap();
    let metadata = fs::symlink_metadata(&guard.target.path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.mode() & 0o7777, 0o660);
    assert_eq!(metadata.nlink(), 1);

    fs::remove_file(&guard.target.path).unwrap();
    let attacker = StdUnixListener::bind(&guard.target.path).unwrap();
    fs::set_permissions(&guard.target.path, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(guard.validate().is_err());
    drop(listener);
    drop(guard);
    assert!(fs::symlink_metadata(config.listen_socket).is_ok());
    drop(attacker);
}

#[tokio::test]
async fn stale_listener_and_symlink_parent_fail_before_binding() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710)).unwrap();
    let stale_path = directory.path().join("issuer-rpc");
    fs::write(&stale_path, b"stale").unwrap();
    let config = listener_config(stale_path);
    assert!(create_listener(&config).is_err());

    let outer = tempfile::tempdir().unwrap();
    let real = outer.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o710)).unwrap();
    let alias = outer.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let config = listener_config(alias.join("issuer-rpc"));
    assert!(create_listener(&config).is_err());
}

#[test]
fn configuration_forbids_root_shared_identity_and_direct_issuer_upstream_access() {
    let base = || Cli {
        listen_socket: PathBuf::from("/run/bitcoinpir-cln-guard/issuer-rpc"),
        upstream_socket: PathBuf::from("/run/lightning/signet/lightning-rpc"),
        guard_uid: 1001,
        guard_gid: 1002,
        issuer_uid: 1003,
        issuer_gid: 1004,
        upstream_expected_uid: 1005,
        upstream_expected_gid: Some(1002),
        timeout_seconds: 10,
        max_in_flight: 32,
        max_invoice_msat: 100_000_000,
        max_invoices_per_minute: 60,
        max_invoice_burst: 10,
        max_invoices_per_runtime: 10_000,
    };
    assert!(GuardConfig::try_from(base()).is_ok());

    let mut root = base();
    root.guard_uid = 0;
    assert!(GuardConfig::try_from(root).is_err());
    let mut shared = base();
    shared.issuer_uid = shared.guard_uid;
    assert!(GuardConfig::try_from(shared).is_err());
    let mut direct_owner = base();
    direct_owner.upstream_expected_uid = direct_owner.issuer_uid;
    assert!(GuardConfig::try_from(direct_owner).is_err());
    let mut direct_group = base();
    direct_group.upstream_expected_gid = Some(direct_group.issuer_gid);
    assert!(GuardConfig::try_from(direct_group).is_err());
    let mut unpinned_group = base();
    unpinned_group.upstream_expected_gid = Some(1006);
    assert!(GuardConfig::try_from(unpinned_group).is_err());
    let mut no_cross_uid_group = base();
    no_cross_uid_group.upstream_expected_gid = None;
    assert!(GuardConfig::try_from(no_cross_uid_group).is_err());
    let mut zero_amount = base();
    zero_amount.max_invoice_msat = 0;
    assert!(GuardConfig::try_from(zero_amount).is_err());
    let mut excessive_amount = base();
    excessive_amount.max_invoice_msat = MAX_BITCOIN_MSAT_V1 + 1;
    assert!(GuardConfig::try_from(excessive_amount).is_err());
    let mut zero_rate = base();
    zero_rate.max_invoices_per_minute = 0;
    assert!(GuardConfig::try_from(zero_rate).is_err());
    let mut excessive_rate = base();
    excessive_rate.max_invoices_per_minute = MAX_INVOICES_PER_MINUTE_V1 + 1;
    assert!(GuardConfig::try_from(excessive_rate).is_err());
    let mut zero_burst = base();
    zero_burst.max_invoice_burst = 0;
    assert!(GuardConfig::try_from(zero_burst).is_err());
    let mut excessive_burst = base();
    excessive_burst.max_invoice_burst = MAX_INVOICE_BURST_V1 + 1;
    assert!(GuardConfig::try_from(excessive_burst).is_err());
    let mut burst_over_rate = base();
    burst_over_rate.max_invoice_burst = burst_over_rate.max_invoices_per_minute + 1;
    assert!(GuardConfig::try_from(burst_over_rate).is_err());
    let mut zero_runtime = base();
    zero_runtime.max_invoices_per_runtime = 0;
    assert!(GuardConfig::try_from(zero_runtime).is_err());
    let mut excessive_runtime = base();
    excessive_runtime.max_invoices_per_runtime = MAX_INVOICES_PER_RUNTIME_V1 + 1;
    assert!(GuardConfig::try_from(excessive_runtime).is_err());
}
