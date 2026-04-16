//! Build script for the `tinytun` user-space crate.
//!
//! When the `ebpf-inbound` feature is enabled **and** the build host is
//! Linux, this script compiles the `tinytun-ebpf` eBPF program using the
//! nightly Rust toolchain and `bpf-linker`, then copies the resulting ELF
//! object into `OUT_DIR` so that [`src/ebpf_inbound.rs`] can embed it at
//! compile time with `include_bytes!`.
//!
//! **Prerequisites** (only required when `--features ebpf-inbound` is used):
//! ```sh
//! rustup toolchain install nightly
//! rustup component add rust-src --toolchain nightly
//! cargo install bpf-linker
//! ```

fn main() {
    // Only build eBPF when the feature is explicitly requested AND we are on Linux.
    let ebpf_feature = std::env::var("CARGO_FEATURE_EBPF_INBOUND").is_ok();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if !ebpf_feature || target_os != "linux" {
        return;
    }

    // Use aya-build to compile the tinytun-ebpf package.
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "tinytun-ebpf",
            root_dir: "tinytun-ebpf",
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Nightly,
    )
    .expect("Failed to build tinytun-ebpf eBPF program");
}
