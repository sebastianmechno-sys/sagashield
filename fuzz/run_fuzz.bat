@echo off
REM Coverage-guided fuzzing for SagaShield security guards (Windows).
REM Requires: nightly toolchain + cargo-fuzz.
REM
REM   rustup toolchain install nightly --profile minimal
REM   cargo install cargo-fuzz
REM
REM The deterministic hostile corpus (>1.300 inputs) already runs on stable:
REM   cargo test --test security_fuzz_test
REM Use the fuzzers below for open-ended exploration.

cd /d "%~dp0"

echo [1/2] path_guard (sandbox escape invariant) ...
cargo +nightly fuzz run path_guard -- -max_total_time=300 -print_final_stats=1 -max_len=512
if errorlevel 1 exit /b %errorlevel%

echo [2/2] net_guard (whitelist bypass invariant) ...
cargo +nightly fuzz run net_guard -- -max_total_time=300 -print_final_stats=1 -max_len=256
if errorlevel 1 exit /b %errorlevel%

echo Fuzzing done. Crashes (if any) are in fuzz\artifacts\.
