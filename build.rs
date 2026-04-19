// build.rs – TinyTun pre-build steps.
//
// When the `ebpf` feature is enabled on a Linux host this script compiles the
// eBPF kernel object (`ebpf/` workspace member) using Rust nightly so that
// `ebpf_loader.rs` can embed it with `include_bytes!` at compile time.
//
// The script is a no-op on non-Linux hosts and when the `ebpf` feature is
// disabled, so it does not affect cross-compilation or Windows/macOS builds.
//
// ## Why `rustup run nightly` instead of `cargo +nightly`
//
// When Cargo runs a build script it prepends the *current* toolchain's bin
// directory to PATH, so `Command::new("cargo")` resolves to the real stable
// cargo binary (not the rustup shim).  That binary does not understand the
// `+nightly` override, so `-Z build-std` ends up looking for rust-src under
// the stable sysroot and panics.  `rustup run nightly -- cargo` is the
// portable fix: it always sets up the full nightly environment regardless of
// the outer toolchain or environment variables.

fn main() {
    // Only relevant on Linux with the ebpf feature enabled.
    #[cfg(target_os = "linux")]
    if std::env::var_os("CARGO_FEATURE_EBPF").is_some() {
        build_ebpf_object();
    }
}

#[cfg(target_os = "linux")]
fn build_ebpf_object() {
    use std::process::Command;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");
    let ebpf_dir = format!("{}/ebpf", manifest_dir);

    // Re-run this build script whenever the eBPF source or manifest changes.
    println!("cargo:rerun-if-changed={}/src/main.rs", ebpf_dir);
    println!("cargo:rerun-if-changed={}/Cargo.toml", ebpf_dir);

    let ebpf_output = format!(
        "{}/target/bpfel-unknown-none/release/tinytun-ebpf",
        ebpf_dir
    );

    // Skip the nightly invocation when the object is already up-to-date.
    // This lets build.sh and CI pre-build the eBPF object in a dedicated step
    // so the main `cargo build` call is fast (no redundant nightly round-trip).
    if ebpf_is_fresh(&ebpf_dir, &ebpf_output) {
        return;
    }

    // Use `rustup run nightly -- cargo` to guarantee the nightly toolchain is
    // active.  Additionally clear Cargo-injected env vars (CARGO, RUSTC,
    // RUSTUP_TOOLCHAIN, …) that would otherwise leak the outer stable sysroot
    // into the subprocess and cause -Z build-std to look in the wrong place.
    let status = Command::new("rustup")
        .args([
            "run", "nightly", "--",
            "cargo", "build",
            "-Z", "build-std=core",
            "--target", "bpfel-unknown-none",
            "--release",
        ])
        .current_dir(&ebpf_dir)
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(_) => {
            panic!(
                "\n\neBPF kernel object build failed.\n\
                 Ensure you have Rust nightly and rust-src installed:\n\
                 \n  rustup toolchain install nightly\n\
                 \n  rustup component add rust-src --toolchain nightly\n\
                 \nThen retry, or build without eBPF support:\n\
                 \n  cargo build --release  (no --features ebpf)\n"
            );
        }
        Err(e) => {
            panic!(
                "\n\nFailed to invoke `rustup run nightly` to build the eBPF object: {}\n\
                 Is rustup and the nightly toolchain installed?\n\
                 \n  rustup toolchain install nightly\n\
                 \n  rustup component add rust-src --toolchain nightly\n",
                e
            );
        }
    }
}

/// Returns `true` when the pre-compiled eBPF object at `output_path` is newer
/// than (or the same age as) all tracked source files inside `ebpf_dir`.
///
/// Used to skip a redundant nightly invocation when the object was already
/// built by an external step (CI action, `build.sh`, etc.).
#[cfg(target_os = "linux")]
fn ebpf_is_fresh(ebpf_dir: &str, output_path: &str) -> bool {
    let out_mtime = match std::fs::metadata(output_path).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return false, // output missing or unreadable — must build
    };

    let sources = [
        format!("{}/src/main.rs", ebpf_dir),
        format!("{}/Cargo.toml", ebpf_dir),
    ];

    for src in &sources {
        if let Ok(src_mtime) = std::fs::metadata(src).and_then(|m| m.modified()) {
            if src_mtime > out_mtime {
                return false; // source is newer than output — rebuild
            }
        }
    }

    true
}
