use datafusion::arrow::array::{ArrayRef, Int32Array, RecordBatch, StringArray};
use datafusion::dataframe::DataFrameWriteOptions;
use datafusion::datasource::file_format::parquet::ParquetFormat;
use datafusion::datasource::listing::ListingOptions;
use datafusion::parquet::arrow::arrow_reader::{ArrowReaderMetadata, ArrowReaderOptions};
use datafusion::parquet::file::column_crypto_metadata::ColumnCryptoMetaData;
use datafusion::prelude::SessionContext;
use datafusion_common::config::TableParquetOptions;
use futures::StreamExt;
use parquet_key_management::crypto_factory::{
    CryptoFactory, DecryptionConfiguration, EncryptionConfiguration,
};
use parquet_key_management::datafusion::{KmsEncryptionFactory, KmsEncryptionFactoryOptions};
use parquet_key_management::kms::KmsConnectionConfig;
use parquet_key_management::test_kms::TestKmsClientFactory;
use std::fs::File;
use std::sync::Arc;
use tempfile::TempDir;

const ENCRYPTION_FACTORY_ID: &str = "example.memory_kms_encryption";

#[tokio::test]
async fn write_and_read_datafusion_table() {
    let ctx = SessionContext::new();
    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());

    let kms_connection_config = Arc::new(KmsConnectionConfig::default());
    let encryption_factory = Arc::new(KmsEncryptionFactory::new(
        crypto_factory,
        kms_connection_config,
    ));
    ctx.runtime_env()
        .register_parquet_encryption_factory(ENCRYPTION_FACTORY_ID, encryption_factory);

    // Register some simple test data
    let a: ArrayRef = Arc::new(StringArray::from(vec!["a", "b", "c", "a", "b", "c"]));
    let b: ArrayRef = Arc::new(Int32Array::from(vec![1, 10, 10, 100, 110, 111]));
    let c: ArrayRef = Arc::new(Int32Array::from(vec![2, 20, 20, 200, 220, 222]));
    let d: ArrayRef = Arc::new(Int32Array::from(vec![3, 30, 30, 300, 330, 333]));
    let batch = RecordBatch::try_from_iter(vec![("a", a), ("b", b), ("c", c), ("d", d)]).unwrap();
    ctx.register_batch("test_data", batch).unwrap();

    // Configure encryption and decryption options
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .add_column_key("kc1".into(), vec!["b".into()])
        .add_column_key("kc2".into(), vec!["c".into()])
        .build()
        .unwrap();
    let decryption_config = DecryptionConfiguration::builder().build();
    let kms_options = KmsEncryptionFactoryOptions::new(encryption_config, decryption_config);

    let tmpdir = TempDir::new().unwrap();
    let table_path = format!("{}/", tmpdir.path().to_str().unwrap());
    write_encrypted(&ctx, &table_path, &kms_options)
        .await
        .unwrap();
    read_encrypted(&ctx, &table_path, &kms_options)
        .await
        .unwrap();
    verify_encryption(&table_path).unwrap();
}

async fn write_encrypted(
    ctx: &SessionContext,
    table_path: &str,
    kms_options: &KmsEncryptionFactoryOptions,
) -> datafusion::common::Result<()> {
    let df = ctx.table("test_data").await?;

    let mut parquet_options = TableParquetOptions::new();
    parquet_options
        .crypto
        .configure_factory(ENCRYPTION_FACTORY_ID, kms_options);

    let df_write_options =
        DataFrameWriteOptions::default().with_partition_by(vec!["a".to_string()]);
    df.write_parquet(table_path, df_write_options, Some(parquet_options))
        .await?;

    Ok(())
}

/// Read from an encrypted Parquet file
async fn read_encrypted(
    ctx: &SessionContext,
    table_path: &str,
    kms_options: &KmsEncryptionFactoryOptions,
) -> datafusion::common::Result<()> {
    let mut parquet_options = TableParquetOptions::new();
    parquet_options
        .crypto
        .configure_factory(ENCRYPTION_FACTORY_ID, kms_options);

    let file_format = ParquetFormat::default().with_options(parquet_options);
    let listing_options = ListingOptions::new(Arc::new(file_format));

    ctx.register_listing_table(
        "encrypted_parquet_table",
        &table_path,
        listing_options.clone(),
        None,
        None,
    )
    .await?;

    let mut batch_stream = ctx
        .table("encrypted_parquet_table")
        .await?
        .execute_stream()
        .await?;
    let mut total_rows = 0;
    while let Some(batch) = batch_stream.next().await {
        let batch = batch?;
        total_rows += batch.num_rows();
    }

    assert_eq!(total_rows, 6);

    Ok(())
}

fn verify_encryption(table_path: &str) -> datafusion::common::Result<()> {
    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
    let mut dirs = vec![std::path::PathBuf::from(table_path)];
    let mut files_visited = 0;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "parquet") {
                verify_parquet_file(&path, &crypto_factory)?;
                files_visited += 1;
            }
        }
    }
    assert_eq!(files_visited, 3);
    Ok(())
}

fn verify_parquet_file(
    file_path: &std::path::Path,
    crypto_factory: &CryptoFactory,
) -> datafusion::common::Result<()> {
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let decryption_config = DecryptionConfiguration::builder().build();
    let decryption_properties =
        crypto_factory.file_decryption_properties(kms_config, decryption_config)?;

    let reader_options =
        ArrowReaderOptions::new().with_file_decryption_properties(decryption_properties);
    let file = File::open(file_path)?;
    let reader_metadata = ArrowReaderMetadata::load(&file, reader_options)?;
    let metadata = reader_metadata.metadata();
    assert!(metadata.num_row_groups() > 0);
    for row_group in metadata.row_groups() {
        let col_b = row_group.column(0);
        assert!(matches!(
            col_b.crypto_metadata(),
            Some(ColumnCryptoMetaData::ENCRYPTION_WITH_COLUMN_KEY(_))
        ));
        let col_c = row_group.column(1);
        assert!(matches!(
            col_c.crypto_metadata(),
            Some(ColumnCryptoMetaData::ENCRYPTION_WITH_COLUMN_KEY(_))
        ));
        let col_d = row_group.column(2);
        assert!(col_d.crypto_metadata().is_none());
    }

    Ok(())
}
