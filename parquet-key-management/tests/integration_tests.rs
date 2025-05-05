//! Tests reading encrypted files that may have been written by another Parquet implementation

use arrow_array::RecordBatch;
use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
use parquet::errors::Result;
use parquet_key_management::crypto_factory::{CryptoFactory, DecryptionConfiguration};
use parquet_key_management::kms::KmsConnectionConfig;
use parquet_key_management::test_kms::TestKmsClientFactory;
use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
#[ignore = "Integration test must be run explicitly after setting PARQUET_ENCRYPTION_DATA_DIR"]
fn read_integration_test_files() {
    let data_directory = env::var("PARQUET_ENCRYPTION_DATA_DIR")
        .expect("PARQUET_ENCRYPTION_DATA_DIR environment variable not set");
    let data_directory = PathBuf::from(data_directory);

    let unencrypted_file_name = "unencrypted.parquet";
    let expected_data =
        read_parquet_file(data_directory.join(unencrypted_file_name), None).unwrap();

    let file_paths = std::fs::read_dir(data_directory).unwrap();
    for dir_entry in file_paths {
        let dir_entry = dir_entry.unwrap();
        if dir_entry.file_name() != unencrypted_file_name {
            let read_data =
                read_parquet_file(dir_entry.path(), Some(DecryptionConfiguration::default()))
                    .unwrap();

            assert_eq!(expected_data, read_data);
        }
    }
}

fn read_parquet_file(
    path: PathBuf,
    decryption_config: Option<DecryptionConfiguration>,
) -> Result<Vec<RecordBatch>> {
    let mut reader_options = ArrowReaderOptions::new();
    if let Some(decryption_config) = decryption_config {
        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let decryption_properties =
            crypto_factory.file_decryption_properties(kms_config, decryption_config)?;

        reader_options = reader_options.with_file_decryption_properties(decryption_properties);
    }

    let file = File::open(&path)?;

    let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(file, reader_options)?;
    let record_reader = builder.build()?;
    let mut batches = Vec::new();
    for batch in record_reader {
        let batch = batch?;
        batches.push(batch);
    }
    Ok(batches)
}
