use arrow_array::{ArrayRef, Float32Array, RecordBatch};
use parquet::arrow::ArrowWriter;
use parquet::file::column_crypto_metadata::ColumnCryptoMetaData;
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::file::properties::WriterProperties;
use parquet_key_management::config::{DecryptionConfiguration, EncryptionConfiguration};
use parquet_key_management::crypto_factory::CryptoFactory;
use parquet_key_management::key_material::KeyMaterial;
use parquet_key_management::kms::test::TestKmsClientFactory;
use parquet_key_management::kms::KmsConnectionConfig;
use std::fs::File;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn can_read_key_material() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.parquet");

    let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
    let kms_config = Arc::new(KmsConnectionConfig::default());

    {
        let file = File::create(&file_path).unwrap();

        let encryption_config = EncryptionConfiguration::builder("kf".into())
            .set_double_wrapping(true)
            .add_column_key("kc1".into(), vec!["x".into()])
            .build()
            .unwrap();
        let encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let writer_properties = WriterProperties::builder()
            .with_file_encryption_properties(encryption_properties)
            .build();

        let x_vals = Float32Array::from(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5]);
        let write_batch =
            RecordBatch::try_from_iter(vec![("x", Arc::new(x_vals) as ArrayRef)]).unwrap();

        let mut writer =
            ArrowWriter::try_new(file, write_batch.schema(), Some(writer_properties)).unwrap();

        writer.write(&write_batch).unwrap();
        writer.close().unwrap();
    }

    let file = File::open(&file_path).unwrap();

    let decryption_config = DecryptionConfiguration::default();
    let decryption_properties = crypto_factory
        .file_decryption_properties(kms_config.clone(), decryption_config)
        .unwrap();

    let reader =
        ParquetMetaDataReader::new().with_decryption_properties(Some(&decryption_properties));
    let metadata = reader.parse_and_finish(&file).unwrap();
    let column_metadata = metadata.row_group(0).column(0);
    let column_crypto = column_metadata.crypto_metadata().unwrap();
    match column_crypto {
        ColumnCryptoMetaData::EncryptionWithFooterKey => {
            panic!("Expected encryption with a column key")
        }
        ColumnCryptoMetaData::EncryptionWithColumnKey(column_key) => {
            let key_material = column_key.key_metadata.as_ref().unwrap();
            let key_material = std::str::from_utf8(key_material).unwrap();
            let key_material = KeyMaterial::deserialize(key_material).unwrap();

            assert_eq!(key_material.master_key_id, "kc1");
            assert!(key_material.double_wrapping);
        }
    }
}
