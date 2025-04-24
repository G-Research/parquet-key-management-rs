# parquet-key-management-rs

This library implements the Parquet Key Management Tools API in Rust
to enable using a Key Management Server (KMS) to write and read encrypted Parquet files.
It is used in conjunction with the Parquet modular encryption support
in the [parquet crate](https://crates.io/crates/parquet).

This library can be used to write and read encrypted Parquet
files that are compatible with other Parquet implementations, for example
[PyArrow](https://arrow.apache.org/docs/python/parquet.html#parquet-modular-encryption-columnar-encryption)
and [Apache Spark](https://spark.apache.org/docs/latest/sql-data-sources-parquet.html#columnar-encryption).

Concrete KMS client implementations are not included.
To integrate with your KMS client you need to implement
the `KmsClient` trait.
