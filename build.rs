// build.rs – Compiles the BPF C program into an object file that is then
// embedded into the binary via `include_bytes!(env!("BPF_OBJECT_PATH"))`.
//
// This build step only runs when the target OS is Linux.  On other platforms
// the BPF compilation is skipped entirely.
//
// Requirements on the build host (Linux only):
//   • clang (any version that supports `-target bpf`, e.g. clang-15+)
//   • Standard Linux kernel userspace API headers — the `linux/` headers
//     (shipped with `linux-libc-dev` on Debian/Ubuntu, present by default
//      on most Linux development machines).
//
// Note: libbpf-dev is NOT required.  The necessary libbpf helper headers
// (`bpf_helpers.h`, `bpf_endian.h`, `bpf_helper_defs.h`) are vendored in
// `bpf/include/bpf/` and used directly.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only compile BPF programs when targeting Linux.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        return;
    }

    let bpf_src = "bpf/tinytun.bpf.c";

    // Tell Cargo to re-run this build script if the BPF source or vendored
    // headers change.
    println!("cargo:rerun-if-changed={}", bpf_src);
    println!("cargo:rerun-if-changed=bpf/include/bpf/bpf_helpers.h");
    println!("cargo:rerun-if-changed=bpf/include/bpf/bpf_helper_defs.h");
    println!("cargo:rerun-if-changed=bpf/include/bpf/bpf_endian.h");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_obj = PathBuf::from(&out_dir).join("tinytun.bpf.o");

    // Vendored libbpf headers bundled with the source tree.
    // Using these means libbpf-dev does NOT need to be installed.
    let vendored_bpf_inc = "bpf/include";

    // Standard Linux userspace API headers (linux/bpf.h, linux/if_ether.h …).
    // These ship with linux-libc-dev which is present on virtually every Linux
    // development machine.  Prefer the multiarch path if it exists.
    let linux_inc = "/usr/include";
    let rust_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let multiarch_prefix = match rust_arch.as_str() {
        "x86_64"  => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "arm"     => "arm-linux-gnueabihf",
        "riscv64" => "riscv64-linux-gnu",
        _         => "x86_64-linux-gnu",
    };
    let multiarch_inc = format!("/usr/include/{}", multiarch_prefix);

    // Locate clang.
    let clang = find_clang().expect(
        "clang not found – install clang (e.g. `apt-get install clang`). \
         Note: libbpf-dev is NOT required; headers are bundled in bpf/include/.",
    );

    let status = Command::new(&clang)
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            // Vendored libbpf helpers — searched FIRST so they shadow any
            // system-installed libbpf headers.
            &format!("-I{}", vendored_bpf_inc),
            &format!("-I{}", linux_inc),
            &format!("-I{}", multiarch_inc),
            "-c",
            bpf_src,
            "-o",
            out_obj.to_str().unwrap(),
        ])
        .status()
        .unwrap_or_else(|e| panic!("Failed to execute clang ({}): {}", clang, e));

    if !status.success() {
        panic!(
            "BPF compilation failed (exit code {:?}). \
             Make sure clang is installed and linux-libc-dev is present.",
            status.code()
        );
    }

    // Expose the path so the Rust source can do:
    //   include_bytes!(env!("BPF_OBJECT_PATH"))
    println!("cargo:rustc-env=BPF_OBJECT_PATH={}", out_obj.display());
}

fn find_clang() -> Option<String> {
    // Honour the CLANG env var first, then search PATH.
    if let Ok(clang) = std::env::var("CLANG") {
        if !clang.is_empty() {
            return Some(clang);
        }
    }
    for candidate in &["clang", "clang-18", "clang-17", "clang-16", "clang-15"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}
