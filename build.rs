// build.rs – Compiles the BPF C program into an object file that is then
// embedded into the binary via `include_bytes!(env!("BPF_OBJECT_PATH"))`.
//
// Requirements (available in the GitHub Actions environment and on any
// standard Ubuntu/Debian developer workstation):
//   • clang (any version that supports `-target bpf`)
//   • libbpf-dev (provides /usr/include/bpf/bpf_helpers.h)
//   • linux-headers (provides /usr/include/linux/*.h)
//
// If clang is not found the build fails with a clear error message.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let bpf_src = "bpf/tinytun.bpf.c";

    // Tell Cargo to re-run this build script if the BPF source changes.
    println!("cargo:rerun-if-changed={}", bpf_src);

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_obj = PathBuf::from(&out_dir).join("tinytun.bpf.o");

    // Locate clang.
    let clang = find_clang().expect(
        "clang not found – install the `clang` package \
         (e.g. `apt-get install clang libbpf-dev linux-headers-$(uname -r)`)",
    );

    // Determine the best include path for libbpf headers.
    // libbpf-dev puts them under /usr/include/bpf/.
    let bpf_inc = "/usr/include/bpf";
    let linux_inc = "/usr/include";

    // For cross-compiled or multiarch systems the kernel headers can live in
    // an arch-specific subdirectory.
    let multiarch_inc = format!(
        "/usr/include/{}-linux-gnu",
        std::env::var("CARGO_CFG_TARGET_ARCH")
            .as_deref()
            .unwrap_or("x86_64")
            .replace("x86_64", "x86_64")
            .replace("aarch64", "aarch64")
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
            &format!("-I{}", bpf_inc),
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
             Make sure clang and libbpf-dev are installed.",
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
