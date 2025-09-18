//! Generates test files for use in integration tests against other Parquet implementations

use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use parquet_key_management::config::EncryptionConfiguration;
use parquet_key_management::crypto_factory::CryptoFactory;
use parquet_key_management::kms::test::TestKmsClientFactory;
use parquet_key_management::kms::KmsConnectionConfig;
use std::env;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, output_directory] => write_test_files(Path::new(output_directory)),
        _ => Err("Expected a single argument to be provided with the output directory".into()),
    }
}

fn write_test_files(output_directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    write_test_file(&output_directory.join("unencrypted.parquet"), None)?;

    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(false)
        .build()?;
    write_test_file(
        &output_directory.join("uniform_single_wrapped.parquet"),
        Some(encryption_config),
    )?;

    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .build()?;
    write_test_file(
        &output_directory.join("uniform_double_wrapped.parquet"),
        Some(encryption_config),
    )?;

    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(false)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .build()?;
    write_test_file(
        &output_directory.join("per_column_single_wrapped.parquet"),
        Some(encryption_config),
    )?;

    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .build()?;
    write_test_file(
        &output_directory.join("per_column_double_wrapped.parquet"),
        Some(encryption_config),
    )?;

    Ok(())
}

fn write_test_file(
    file_path: &Path,
    encryption_config: Option<EncryptionConfiguration>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(file_path)?;

    let mut writer_properties_builder = WriterProperties::builder();

    if let Some(encryption_config) = encryption_config {
        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_properties =
            crypto_factory.file_encryption_properties(kms_config.clone(), &encryption_config)?;

        writer_properties_builder =
            writer_properties_builder.with_file_encryption_properties(encryption_properties);
    }

    let writer_properties = writer_properties_builder.build();

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

    let mut writer = ArrowWriter::try_new(file, write_batch.schema(), Some(writer_properties))?;

    writer.write(&write_batch)?;
    writer.close()?;

    Ok(())
}
