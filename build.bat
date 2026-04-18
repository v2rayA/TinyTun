@echo off
:: Build script for TinyTun (Windows).
::
:: Usage:
::   build.bat [--target <triple>] [--debug]
::
:: eBPF is not supported on Windows; the main binary is compiled without it.
::
:: Options:
::   --target <triple>   Cross-compile for the given Rust target triple.
::   --debug             Build in debug mode (default: release).

setlocal EnableDelayedExpansion

:: ── Defaults ─────────────────────────────────────────────────────────────────
set "TARGET="
set "PROFILE=--release"

:: ── Argument parsing ──────────────────────────────────────────────────────────
:parse_args
if "%~1"=="" goto :done_args

if "%~1"=="--target" (
    set "TARGET=%~2"
    shift
    shift
    goto :parse_args
)
if "%~1"=="--debug" (
    set "PROFILE="
    shift
    goto :parse_args
)

echo Unknown argument: %~1 1>&2
echo Usage: build.bat [--target ^<triple^>] [--debug] 1>&2
exit /b 1

:done_args

:: ── Build ────────────────────────────────────────────────────────────────────
if defined TARGET (
    set "TARGET_ARG=--target %TARGET%"
) else (
    set "TARGET_ARG="
)

echo =^> Building tinytun (Windows, no eBPF)...
cargo build --locked %PROFILE% %TARGET_ARG%

if %ERRORLEVEL% neq 0 (
    echo.
    echo Build failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

echo.
echo Build complete.
endlocal
