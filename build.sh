#!/usr/bin/env bash
# Build script for TinyTun.
#
# Usage:
#   ./build.sh [--target <triple>] [--release | --debug]
#
# Environment variables:
#   CARGO        Override the cargo binary (default: cargo)
#   CARGO_ARGS   Extra arguments appended to the build command

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
PROFILE="--release"
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
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--target <triple>] [--release|--debug]" >&2
            exit 1 ;;
    esac
done

TARGET_ARG="${TARGET:+--target $TARGET}"

# ── Main build ────────────────────────────────────────────────────────────────
echo "==> Building tinytun..."
# shellcheck disable=SC2086
"${CARGO}" build --locked $PROFILE $TARGET_ARG ${CARGO_ARGS:-}

echo ""
echo "Build complete."
