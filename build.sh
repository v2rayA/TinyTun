#!/usr/bin/env bash
# Build script for TinyTun.
#
# Usage:
#   ./build.sh [--target <triple>] [--release | --debug] [--no-ebpf]
#
# On Linux, the eBPF kernel object is built first (requires Rust nightly +
# rust-src component), then the main binary is compiled with --features ebpf.
# On macOS / FreeBSD / other Unix, only the main binary is compiled.
#
# Environment variables:
#   CARGO        Override the cargo binary (default: cargo)
#   CARGO_ARGS   Extra arguments appended to the main build command

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
PROFILE="--release"
SKIP_EBPF=false
CARGO="${CARGO:-cargo}"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"; shift 2 ;;
        --release)
            PROFILE="--release"; shift ;;
        --debug)
            PROFILE=""; shift ;;
        --no-ebpf)
            SKIP_EBPF=true; shift ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--target <triple>] [--release|--debug] [--no-ebpf]" >&2
            exit 1 ;;
    esac
done

TARGET_ARG="${TARGET:+--target $TARGET}"
OS="$(uname -s)"

# ── Helper: build the eBPF kernel object ─────────────────────────────────────
build_ebpf() {
    echo "==> Checking Rust nightly toolchain..."
    # ebpf/rust-toolchain.toml pins nightly; verify it is installed via rustup.
    if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
        echo ""
        echo "ERROR: Rust nightly toolchain is required to build the eBPF kernel object."
        echo "  Install with:"
        echo "    rustup toolchain install nightly"
        echo "    rustup component add rust-src --toolchain nightly"
        echo ""
        echo "  To skip the eBPF build and compile without eBPF support, run:"
        echo "    ./build.sh --no-ebpf"
        exit 1
    fi

    echo "==> Building eBPF kernel object (bpfel-unknown-none)..."
    pushd ebpf >/dev/null
    # rust-toolchain.toml in ebpf/ selects nightly automatically; no +nightly needed.
    "${CARGO}" build -Z build-std=core --target bpfel-unknown-none --release
    popd >/dev/null
    echo "    Object: ebpf/target/bpfel-unknown-none/release/tinytun-ebpf"
}

# ── Main build ────────────────────────────────────────────────────────────────
if [[ "$OS" == "Linux" ]] && [[ "$SKIP_EBPF" == "false" ]]; then
    build_ebpf
    echo "==> Building tinytun (Linux, with eBPF support)..."
    # shellcheck disable=SC2086
    "${CARGO}" build --locked $PROFILE $TARGET_ARG --features ebpf ${CARGO_ARGS:-}
else
    echo "==> Building tinytun ($OS)..."
    # shellcheck disable=SC2086
    "${CARGO}" build --locked $PROFILE $TARGET_ARG ${CARGO_ARGS:-}
fi

echo ""
echo "Build complete."
if [[ "$OS" == "Linux" ]] && [[ "$SKIP_EBPF" == "false" ]]; then
    echo ""
    echo "NOTE: The eBPF kernel object (tinytun-ebpf.o) must be placed in one of:"
    echo "  - ./ebpf/target/bpfel-unknown-none/release/tinytun-ebpf  (dev, current path)"
    echo "  - /usr/lib/tinytun/tinytun-ebpf.o                        (installed)"
    echo "  - \$TINYTUN_EBPF_OBJECT                                    (env override)"
fi
