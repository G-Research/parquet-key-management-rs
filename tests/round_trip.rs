use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
use parquet::arrow::ArrowWriter;
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
        .build();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn uniform_encryption_double_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .build();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn per_column_encryption_single_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(false)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .build();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
}

#[test]
fn per_column_encryption_double_wrapping() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .build();
    let decryption_config = DecryptionConfiguration::builder().build();

    round_trip_parquet(encryption_config, decryption_config).unwrap();
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
