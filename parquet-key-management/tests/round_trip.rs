use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
use parquet::arrow::ArrowWriter;
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::Result;
use parquet::file::properties::WriterProperties;
use parquet_key_management::crypto_factory::{
    CryptoFactory, DecryptionConfiguration, EncryptionConfiguration,
};
use parquet_key_management::kms::KmsConnectionConfig;
use parquet_key_management::test_kms::TestKmsClientFactory;
use std::fs::File;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn uniform_encryption_single_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(false)
        .build()
        .unwrap();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn uniform_encryption_double_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .build()
        .unwrap();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn per_column_encryption_single_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(false)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .build()
        .unwrap();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn per_column_encryption_double_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .build()
        .unwrap();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn write_with_keys_and_read_with_kms() {
    let footer_key = b"0123456789012345";
    let encryption_properties = FileEncryptionProperties::builder(footer_key.to_vec())
        .build()
        .unwrap();

    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let decryption_config = DecryptionConfiguration::builder().build();
    let decryption_properties = crypto_factory
        .file_decryption_properties(kms_config, decryption_config)
        .unwrap();

    let result = round_trip_parquet_with_properties(encryption_properties, decryption_properties);

    match result {
        Ok(_) => panic!("Expected an error when reading encrypted Parquet that doesn't use a KMS"),
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains(". Perhaps this file was encrypted without using a KMS"));
        }
    }
}

#[test]
fn multi_file_round_trip() {
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
            .unwrap();

        let decryption_config = DecryptionConfiguration::builder().build();
        let decryption_properties = read_crypto_factory
            .file_decryption_properties(kms_config.clone(), decryption_config)
            .unwrap();

        round_trip_parquet_with_properties(encryption_properties, decryption_properties).unwrap()
    }

    assert_eq!(write_client_factory.keys_wrapped(), 3);
    assert_eq!(read_client_factory.keys_unwrapped(), 3);
}

fn round_trip_parquet(
    encryption_config: EncryptionConfiguration,
    decryption_config: DecryptionConfiguration,
) -> Result<()> {
    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let encryption_properties =
        crypto_factory.file_encryption_properties(kms_config.clone(), &encryption_config)?;
    let decryption_properties =
        crypto_factory.file_decryption_properties(kms_config, decryption_config)?;

    round_trip_parquet_with_properties(encryption_properties, decryption_properties)
}

fn round_trip_parquet_with_properties(
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
        let file = File::create(&file_path)?;

        let writer_properties = WriterProperties::builder()
            .with_file_encryption_properties(encryption_properties)
            .build();

        let mut writer = ArrowWriter::try_new(file, write_batch.schema(), Some(writer_properties))?;

        writer.write(&write_batch)?;
        writer.close()?;
    }

    let reader_options =
        ArrowReaderOptions::new().with_file_decryption_properties(decryption_properties);

    let file = File::open(&file_path)?;

    let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(file, reader_options)?;
    let record_reader = builder.build()?;
    for batch in record_reader {
        let read_batch = batch?;
        assert_eq!(write_batch, read_batch);
    }

    Ok(())
}
