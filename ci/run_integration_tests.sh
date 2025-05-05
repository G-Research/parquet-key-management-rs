#!/bin/bash

set -e

# Default to RUNNER_TEMP dir, which is set when running in GitHub Actions
DATA_DIR=${RUNNER_TEMP:-/tmp}
RUST_DATA_DIR="${DATA_DIR}/parquet_rust_test_data"

mkdir -p "${RUST_DATA_DIR}"

# Generate test files with Rust
cargo run --bin generate-test-files -- "${RUST_DATA_DIR}"

# Read test files with Rust
PARQUET_ENCRYPTION_DATA_DIR="${RUST_DATA_DIR}" cargo test --test integration_tests -- --ignored
