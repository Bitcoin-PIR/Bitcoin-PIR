//! Captures the git commit hash at build time so the running binary
//! can report it via /attest. Falls back to "unknown" if `git` isn't
//! available or the source tree isn't a git checkout (e.g. published
//! crate from crates.io).

fn main() {
    let git_rev = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Append "-dirty" if the working tree has uncommitted changes.
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let rev_with_flag = if dirty && git_rev != "unknown" {
        format!("{}-dirty", git_rev)
    } else {
        git_rev
    };

    println!("cargo:rustc-env=BPIR_GIT_REV={}", rev_with_flag);
    // Re-run the build script when HEAD or refs change.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/heads");
}
