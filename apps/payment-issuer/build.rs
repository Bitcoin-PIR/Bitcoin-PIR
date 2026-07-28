use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_ONLY_FAKE_LIGHTNING");

    if env::var_os("CARGO_FEATURE_TEST_ONLY_FAKE_LIGHTNING").is_none() {
        return;
    }

    // `debug_assertions` alone is not a Cargo-profile boundary: an operator
    // can enable it in an otherwise release/production profile. Keep the
    // source-level cfg guard as defense in depth, but also reject this feature
    // unless Cargo is building its debug/test artifact class.
    let profile = env::var("PROFILE").unwrap_or_default();
    if profile != "debug" {
        panic!("test-only-fake-lightning must never be compiled into a production release");
    }
}
