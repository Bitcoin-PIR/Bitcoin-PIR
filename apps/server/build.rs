use std::env;

const UNSAFE_QUERY_LOGGING_FEATURE_ENV: &str = "CARGO_FEATURE_TEST_ONLY_UNSAFE_QUERY_LOGGING";

fn main() {
    println!("cargo:rerun-if-env-changed={UNSAFE_QUERY_LOGGING_FEATURE_ENV}");
    println!("cargo:rerun-if-env-changed=PROFILE");

    if env::var_os(UNSAFE_QUERY_LOGGING_FEATURE_ENV).is_none() {
        return;
    }

    let profile = env::var("PROFILE").unwrap_or_else(|_| "<unset>".to_owned());
    assert_eq!(
        profile, "debug",
        "feature `test-only-unsafe-query-logging` is restricted to Cargo's debug profile; got PROFILE={profile}"
    );
}
