#!/bin/bash

set -e
set -x

# Default to RUNNER_TEMP dir, which is set when running in GitHub Actions
DATA_DIR=${RUNNER_TEMP:-/tmp}
RUST_DATA_DIR="${DATA_DIR}/parquet_rust_test_data"
PYTHON_DATA_DIR="${DATA_DIR}/parquet_python_test_data"

mkdir -p "${RUST_DATA_DIR}"
mkdir -p "${PYTHON_DATA_DIR}"

# Generate test files with Rust
cargo run --bin generate-test-files -- "${RUST_DATA_DIR}"

# Generate test files with Python
pushd pyarrow-integration-tests
uv run generate_test_files "${PYTHON_DATA_DIR}"
popd

# Read test files with Rust
PARQUET_ENCRYPTION_DATA_DIR="${RUST_DATA_DIR}" cargo test --test integration_tests --verbose -- --ignored
PARQUET_ENCRYPTION_DATA_DIR="${PYTHON_DATA_DIR}" cargo test --test integration_tests --verbose -- --ignored

# Read test files with Python
pushd pyarrow-integration-tests
PARQUET_ENCRYPTION_DATA_DIR="${PYTHON_DATA_DIR}" uv run pytest -v
PARQUET_ENCRYPTION_DATA_DIR="${RUST_DATA_DIR}" uv run pytest -v
popd
