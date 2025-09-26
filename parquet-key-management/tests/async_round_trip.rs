use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use futures::TryStreamExt;
use parquet::arrow::arrow_reader::ArrowReaderOptions;
use parquet::arrow::{AsyncArrowWriter, ParquetRecordBatchStreamBuilder};
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::Result;
use parquet::file::properties::WriterProperties;
use parquet_key_management::async_crypto_factory::CryptoFactory;
use parquet_key_management::async_kms::test::TestKmsClientFactory;
use parquet_key_management::async_kms::KmsConnectionConfig;
use parquet_key_management::config::{DecryptionConfiguration, EncryptionConfiguration};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn write_with_keys_and_read_with_async_kms() {
    let footer_key = b"0123456789012345";
    let encryption_properties = FileEncryptionProperties::builder(footer_key.to_vec())
        .build()
        .unwrap();

    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let decryption_config = DecryptionConfiguration::builder().build();
    let decryption_properties = crypto_factory
        .file_decryption_properties(kms_config, decryption_config)
        .await
        .unwrap();

    let result =
        round_trip_parquet_with_properties(encryption_properties, decryption_properties).await;

    match result {
        Ok(_) => panic!("Expected an error when reading encrypted Parquet that doesn't use a KMS"),
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains(". Perhaps this file was encrypted without using a KMS"));
        }
    }
}

#[tokio::test]
async fn multi_file_round_trip_with_async_kms() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .set_cache_lifetime(None)
        .build()
        .unwrap();

    let write_client_factory = Arc::new(TestKmsClientFactory::with_default_keys());
    let read_client_factory = Arc::new(TestKmsClientFactory::with_default_keys());

    let write_crypto_factory = CryptoFactory::new(write_client_factory.clone());
    let read_crypto_factory = CryptoFactory::new(read_client_factory.clone());

    let kms_config = Arc::new(KmsConnectionConfig::default());

    for _ in 0..5 {
        let encryption_properties = write_crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let decryption_config = DecryptionConfiguration::builder().build();
        let decryption_properties = read_crypto_factory
            .file_decryption_properties(kms_config.clone(), decryption_config)
            .await
            .unwrap();

        round_trip_parquet_with_properties(encryption_properties, decryption_properties)
            .await
            .unwrap()
    }

    assert_eq!(write_client_factory.keys_wrapped(), 3);
    assert_eq!(read_client_factory.keys_unwrapped(), 3);
}

async fn round_trip_parquet_with_properties(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("test_file.parquet");

    let ids = Int32Array::from(vec![0, 1, 2, 3, 4, 5]);
    let x_vals = Float32Array::from(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5]);
    let y_vals = Float32Array::from(vec![1.0, 1.1, 1.2, 1.3, 1.4, 1.5]);
    let z_vals = Float32Array::from(vec![2.0, 2.1, 2.2, 2.3, 2.4, 2.5]);
    let write_batch = RecordBatch::try_from_iter(vec![
        ("id", Arc::new(ids) as ArrayRef),
        ("x", Arc::new(x_vals) as ArrayRef),
        ("y", Arc::new(y_vals) as ArrayRef),
        ("z", Arc::new(z_vals) as ArrayRef),
    ])?;

    {
        let file = tokio::fs::File::create(&file_path).await?;

        let writer_properties = WriterProperties::builder()
            .with_file_encryption_properties(encryption_properties)
            .build();

        let mut writer =
            AsyncArrowWriter::try_new(file, write_batch.schema(), Some(writer_properties))?;

        writer.write(&write_batch).await?;
        writer.close().await?;
    }

    let reader_options =
        ArrowReaderOptions::new().with_file_decryption_properties(decryption_properties);

    let file = tokio::fs::File::open(&file_path).await?;

    let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, reader_options).await?;
    let stream = builder.build()?;
    let results = stream.try_collect::<Vec<_>>().await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], write_batch);

    Ok(())
}
