use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use futures::TryStreamExt;
use parquet::arrow::arrow_reader::ArrowReaderOptions;
use parquet::arrow::{AsyncArrowWriter, ParquetRecordBatchStreamBuilder};
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::Result;
use parquet::file::properties::WriterProperties;
use parquet_key_management::crypto_factory::{
    CryptoFactory, DecryptionConfiguration, EncryptionConfiguration,
};
use parquet_key_management::kms::KmsConnectionConfig;
use parquet_key_management::test_kms::TestAsyncKmsClientFactory;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[allow(dead_code)]
async fn write_with_keys_and_read_with_async_kms<CF, RF, Fut>(
    crypto_factory_fn: CF,
    round_trip_fn: RF,
) where
    CF: Fn(TestAsyncKmsClientFactory) -> CryptoFactory,
    RF: Fn(FileEncryptionProperties, FileDecryptionProperties) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let footer_key = b"0123456789012345";
    let encryption_properties = FileEncryptionProperties::builder(footer_key.to_vec())
        .build()
        .unwrap();

    let crypto_factory = crypto_factory_fn(TestAsyncKmsClientFactory::with_default_keys());
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let decryption_config = DecryptionConfiguration::builder().build();
    let decryption_properties = crypto_factory
        .file_decryption_properties(kms_config, decryption_config)
        .unwrap();

    let result = round_trip_fn(encryption_properties, decryption_properties).await;

    match result {
        Ok(_) => panic!("Expected an error when reading encrypted Parquet that doesn't use a KMS"),
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains(". Perhaps this file was encrypted without using a KMS"));
        }
    }
}

#[allow(dead_code)]
async fn multi_file_round_trip_with_async_kms<CF, RF, Fut>(crypto_factory_fn: CF, round_trip_fn: RF)
where
    CF: Fn(Arc<TestAsyncKmsClientFactory>) -> CryptoFactory,
    RF: Fn(FileEncryptionProperties, FileDecryptionProperties) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .set_cache_lifetime(None)
        .build()
        .unwrap();

    let write_client_factory = Arc::new(TestAsyncKmsClientFactory::with_default_keys());
    let read_client_factory = Arc::new(TestAsyncKmsClientFactory::with_default_keys());

    let write_crypto_factory = crypto_factory_fn(write_client_factory.clone());
    let read_crypto_factory = crypto_factory_fn(read_client_factory.clone());

    let kms_config = Arc::new(KmsConnectionConfig::default());

    for _ in 0..5 {
        let encryption_properties = write_crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let decryption_config = DecryptionConfiguration::builder().build();
        let decryption_properties = read_crypto_factory
            .file_decryption_properties(kms_config.clone(), decryption_config)
            .unwrap();

        round_trip_fn(encryption_properties, decryption_properties)
            .await
            .unwrap()
    }

    assert_eq!(write_client_factory.keys_wrapped(), 3);
    assert_eq!(read_client_factory.keys_unwrapped(), 3);
}

#[allow(dead_code)]
async fn round_trip_parquet_with_properties<W, R, CFut, OFut, CFn, OFn>(
    create_fn: CFn,
    open_fn: OFn,
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()>
where
    W: AsyncWrite + Send + Unpin,
    R: AsyncRead + AsyncSeek + Send + Unpin + 'static,
    CFn: Fn(&Path) -> CFut,
    OFn: Fn(&Path) -> OFut,
    CFut: Future<Output = Result<W>>,
    OFut: Future<Output = Result<R>>,
{
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
        let file = create_fn(&file_path).await?;

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

    let file = open_fn(&file_path).await?;

    let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, reader_options).await?;
    let stream = builder.build()?;
    let results = stream.try_collect::<Vec<_>>().await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], write_batch);

    Ok(())
}

#[cfg(feature = "async-std")]
#[test]
fn write_with_keys_and_read_with_async_kms_async_std() {
    async_std::task::block_on(async {
        write_with_keys_and_read_with_async_kms(
            CryptoFactory::new_async_with_async_std,
            round_trip_parquet_with_properties_async_std,
        )
        .await
    })
}

#[cfg(feature = "async-std")]
#[test]
fn multi_file_round_trip_with_async_kms_async_std() {
    async_std::task::block_on(async {
        multi_file_round_trip_with_async_kms(
            CryptoFactory::new_async_with_async_std,
            round_trip_parquet_with_properties_async_std,
        )
        .await
    })
}

#[cfg(feature = "async-std")]
async fn round_trip_parquet_with_properties_async_std(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    use async_compat::CompatExt;

    round_trip_parquet_with_properties(
        |path| {
            let path = path.to_owned();
            async move { Ok(async_std::fs::File::create(path).await?.compat()) }
        },
        |path| {
            let path = path.to_owned();
            async move { Ok(async_std::fs::File::open(path).await?.compat()) }
        },
        encryption_properties,
        decryption_properties,
    )
    .await
}

#[cfg(feature = "smol")]
#[test]
fn write_with_keys_and_read_with_async_kms_smol() {
    smol::future::block_on(smol::LocalExecutor::new().run(async {
        write_with_keys_and_read_with_async_kms(
            CryptoFactory::new_async_with_smol,
            round_trip_parquet_with_properties_smol,
        )
        .await
    }))
}

#[cfg(feature = "smol")]
#[test]
fn multi_file_round_trip_with_async_kms_smol() {
    smol::future::block_on(smol::LocalExecutor::new().run(async {
        multi_file_round_trip_with_async_kms(
            CryptoFactory::new_async_with_smol,
            round_trip_parquet_with_properties_smol,
        )
        .await
    }))
}

#[cfg(feature = "smol")]
async fn round_trip_parquet_with_properties_smol(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    use async_compat::CompatExt;

    round_trip_parquet_with_properties(
        |path| {
            let path = path.to_owned();
            async move { Ok(smol::fs::File::create(path).await?.compat()) }
        },
        |path| {
            let path = path.to_owned();
            async move { Ok(smol::fs::File::open(path).await?.compat()) }
        },
        encryption_properties,
        decryption_properties,
    )
    .await
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn write_with_keys_and_read_with_async_kms_tokio() {
    write_with_keys_and_read_with_async_kms(
        CryptoFactory::new_async_with_tokio,
        round_trip_parquet_with_properties_tokio,
    )
    .await
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn multi_file_round_trip_with_async_kms_tokio() {
    multi_file_round_trip_with_async_kms(
        CryptoFactory::new_async_with_tokio,
        round_trip_parquet_with_properties_tokio,
    )
    .await
}

#[cfg(feature = "tokio")]
async fn round_trip_parquet_with_properties_tokio(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    round_trip_parquet_with_properties(
        |path| {
            let path = path.to_owned();
            async move { Ok(tokio::fs::File::create(path).await?) }
        },
        |path| {
            let path = path.to_owned();
            async move { Ok(tokio::fs::File::open(path).await?) }
        },
        encryption_properties,
        decryption_properties,
    )
    .await
}
