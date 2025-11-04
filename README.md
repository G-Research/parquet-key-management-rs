# Parquet Key Management for Rust

[![crates.io](https://img.shields.io/crates/v/parquet-key-management.svg)](https://crates.io/crates/parquet-key-management)
[![docs.rs](https://img.shields.io/docsrs/parquet-key-management.svg)](https://docs.rs/parquet-key-management/latest/parquet_key_management/)

This library implements the Parquet Key Management Tools API in Rust
to enable using a Key Management Server (KMS) to write and read encrypted Parquet files.
It is used in conjunction with the Parquet modular encryption support
in the [Apache parquet crate](https://crates.io/crates/parquet).

This library can be used to write and read encrypted Parquet
files that are compatible with other Parquet implementations, for example
[PyArrow](https://arrow.apache.org/docs/python/parquet.html#parquet-modular-encryption-columnar-encryption)
and [Apache Spark](https://spark.apache.org/docs/latest/sql-data-sources-parquet.html#columnar-encryption).

Concrete KMS client implementations are not included.
To integrate with your KMS client you need to implement
the [`KmsClient`](https://docs.rs/parquet-key-management/latest/parquet_key_management/kms/trait.KmsClient.html) or
[`AsyncKmsClient`](https://docs.rs/parquet-key-management/latest/parquet_key_management/kms/trait.AsyncKmsClient.html)
traits.

Please see the [API documentation](https://docs.rs/parquet-key-management/latest/parquet_key_management/)
for examples of how to use this library and the full API reference.

## Feature Flags

The `parquet_key_management` crate provides the following features which may be enabled in your `Cargo.toml`:

- `async` - enables the asynchronous KMS client API
- `async-std` - enables support for the [async-std](https://crates.io/crates/async-std) runtime in the asynchronous KMS client API
- `smol` - enables support for the [smol](https://crates.io/crates/smol) runtime in the asynchronous KMS client API
- `tokio` - enables support for the [Tokio](https://crates.io/crates/tokio) runtime in the asynchronous KMS client API
- `datafusion` - enables the `datafusion` module, which implements integration with [Apache DataFusion](https://datafusion.apache.org/)
