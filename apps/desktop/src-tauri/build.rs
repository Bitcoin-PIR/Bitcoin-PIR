fn main() {
    println!(
        "cargo:rustc-env=BPIR_TARGET_TRIPLE={}",
        std::env::var("TARGET").expect("Cargo sets TARGET for build scripts")
    );
    tauri_build::build()
}
