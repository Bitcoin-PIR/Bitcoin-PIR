//! The production binary answers `--help` and `--version` (exit 0) and still
//! rejects an unknown flag (exit 2), so install sanity checks can call it
//! without starting a server (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #10).

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_unified_server"))
        .args(args)
        .output()
        .expect("spawn unified_server")
}

#[test]
fn version_prints_one_line_and_exits_zero() {
    let out = run(&["--version"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("unified_server "));
    assert!(text.contains(" git_rev=") && text.contains(" binary_sha256="));
}

#[test]
fn help_prints_the_flag_reference_and_exits_zero() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("--serve-queries") && text.contains("--session-grant-pubkey"));
}

#[test]
fn unknown_flag_is_still_rejected() {
    let out = run(&["--no-such-flag"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown argument: --no-such-flag"));
}
