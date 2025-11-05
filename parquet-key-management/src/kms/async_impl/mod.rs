//! Types for integrating with a Key Management Server to use with Parquet Modular Encryption
//! in an asynchronous context.

pub(crate) mod bridge;
pub mod reenter_async;

use crate::kms::KmsConnectionConfig;
use futures::future::BoxFuture;
use parquet::errors::Result;
use std::ops::Deref;
use std::sync::Arc;

/// API for interacting with a KMS asynchronously.
/// This should be implemented by user code for integration with your KMS.
///
/// # Example of writing then reading an encrypted Parquet file asynchronously
/// ```
/// use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
/// use base64::prelude::BASE64_STANDARD;
/// use base64::Engine;
/// use futures::future::BoxFuture;
/// use futures::{FutureExt, TryStreamExt};
/// use parquet::arrow::arrow_reader::ArrowReaderOptions;
/// use parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder;
/// use parquet::arrow::async_writer::AsyncArrowWriter;
/// use parquet::errors::{ParquetError, Result};
/// use parquet::file::properties::WriterProperties;
/// use parquet_key_management::crypto_factory::{
///     CryptoFactory, DecryptionConfiguration, EncryptionConfigurationBuilder,
/// };
/// use parquet_key_management::kms::{AsyncKmsClient, AsyncKmsClientRef, KmsConnectionConfig};
/// use ring::aead::{Aad, LessSafeKey, UnboundKey, AES_128_GCM, NONCE_LEN};
/// use ring::rand::{SecureRandom, SystemRandom};
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use tempfile::TempDir;
/// use tokio::fs::File;
///
/// # #[tokio::main(flavor = "multi_thread")]
/// # async fn main() -> Result<()> {
///     let temp_dir = TempDir::new()?;
///     let file_path = temp_dir.path().join("encrypted_example.parquet");
///
///     // Create a CryptoFactory, providing a factory function
///     // that will create an example KMS client
///     let crypto_factory = CryptoFactory::new_async_with_tokio(DemoKmsClient::create);
///
///     // Specify any options required to connect to our KMS.
///     // These are ignored by the DemoKmsClient but shown here for illustration.
///     // The KMS instance ID and URL will be stored in the Parquet encryption metadata
///     // so don't need to be specified if you are only reading files.
///     let connection_config = Arc::new(
///         KmsConnectionConfig::builder()
///             .set_kms_instance_id("kms1".into())
///             .set_kms_instance_url("https://example.com/kms".into())
///             .set_key_access_token("secret_token".into())
///             .set_custom_kms_conf_option("custom_option".into(), "some_value".into())
///             .build(),
///     );
///
///     // Create an encryption configuration that will encrypt the footer with the "kf" key,
///     // the "x" column with the "kc1" key, and the "y" column with the "kc2" key,
///     // while leaving the "id" column unencrypted.
///     let encryption_config = EncryptionConfigurationBuilder::new("kf".into())
///         .add_column_key("kc1".into(), vec!["x".into()])
///         .add_column_key("kc2".into(), vec!["y".into()])
///         .build()?;
///
///     // Use the CryptoFactory to generate file encryption properties using the configuration
///     let encryption_properties =
///         crypto_factory.file_encryption_properties(connection_config.clone(), &encryption_config)?;
///     let writer_properties = WriterProperties::builder()
///         .with_file_encryption_properties(encryption_properties)
///         .build();
///
///     // Write the encrypted Parquet file
///     {
///         let file = File::create(&file_path).await?;
///
///         let ids = Int32Array::from(vec![0, 1, 2, 3, 4, 5]);
///         let x_vals = Float32Array::from(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5]);
///         let y_vals = Float32Array::from(vec![1.0, 1.1, 1.2, 1.3, 1.4, 1.5]);
///         let batch = RecordBatch::try_from_iter(vec![
///             ("id", Arc::new(ids) as ArrayRef),
///             ("x", Arc::new(x_vals) as ArrayRef),
///             ("y", Arc::new(y_vals) as ArrayRef),
///         ])?;
///
///         let mut writer = AsyncArrowWriter::try_new(file, batch.schema(), Some(writer_properties))?;
///
///         writer.write(&batch).await?;
///         writer.close().await?;
///     }
///
///     // Use the CryptoFactory to generate file decryption properties.
///     // We don't need to specify which columns are encrypted and which keys are used,
///     // that information is stored in the file metadata.
///     let decryption_config = DecryptionConfiguration::default();
///     let decryption_properties =
///         crypto_factory.file_decryption_properties(connection_config, decryption_config)?;
///     let reader_options =
///         ArrowReaderOptions::new().with_file_decryption_properties(decryption_properties);
///
///     // Read the file using the configured decryption properties
///     let file = File::open(&file_path).await?;
///
///     let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, reader_options).await?;
///     let stream = builder.build()?;
///     let batches = stream.try_collect::<Vec<_>>().await?;
///     println!("Read batches: {batches:?}");
///
///     // Example KMS client that uses in-memory AES keys.
///     // A real KMS client should interact with a Key Management Server to encrypt and decrypt keys.
///     pub struct DemoKmsClient {
///         key_map: HashMap<String, Vec<u8>>,
///     }
///
///     impl DemoKmsClient {
///         pub fn create(_config: &KmsConnectionConfig) -> BoxFuture<'_, Result<AsyncKmsClientRef>> {
///             async {
///                 let mut key_map = HashMap::default();
///                 key_map.insert("kf".into(), "0123456789012345".into());
///                 key_map.insert("kc1".into(), "1234567890123450".into());
///                 key_map.insert("kc2".into(), "1234567890123451".into());
///
///                 Ok(Arc::new(Self { key_map }) as AsyncKmsClientRef)
///             }
///             .boxed()
///         }
///
///         // Get the AES key corresponding to a key identifier
///         fn get_key(&self, master_key_identifier: &str) -> Result<LessSafeKey> {
///             let key = self.key_map.get(master_key_identifier).ok_or_else(|| {
///                 ParquetError::General(format!("Invalid master key '{master_key_identifier}'"))
///             })?;
///             let key = UnboundKey::new(&AES_128_GCM, key)
///                 .map_err(|e| ParquetError::General(format!("Error creating AES key '{e}'")))?;
///             Ok(LessSafeKey::new(key))
///         }
///     }
///
///     #[async_trait::async_trait]
///     impl AsyncKmsClient for DemoKmsClient {
///         // Take a randomly generated key and encrypt it using the specified master key
///         async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
///             let master_key = self.get_key(master_key_identifier)?;
///             let aad = master_key_identifier.as_bytes();
///             let rng = SystemRandom::new();
///
///             let mut nonce = [0u8; NONCE_LEN];
///             rng.fill(&mut nonce)?;
///             let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
///
///             let tag_len = master_key.algorithm().tag_len();
///             let mut ciphertext = Vec::with_capacity(NONCE_LEN + key_bytes.len() + tag_len);
///             ciphertext.extend_from_slice(nonce.as_ref());
///             ciphertext.extend_from_slice(key_bytes);
///             let tag = master_key.seal_in_place_separate_tag(
///                 nonce,
///                 Aad::from(aad),
///                 &mut ciphertext[NONCE_LEN..],
///             )?;
///             ciphertext.extend_from_slice(tag.as_ref());
///             let encoded = BASE64_STANDARD.encode(&ciphertext);
///
///             Ok(encoded)
///         }
///
///         // Take an encrypted key and decrypt it using the specified master key identifier
///         async fn unwrap_key(
///             &self,
///             wrapped_key: &str,
///             master_key_identifier: &str,
///         ) -> Result<Vec<u8>> {
///             let wrapped_key = BASE64_STANDARD.decode(wrapped_key).map_err(|e| {
///                 ParquetError::General(format!("Error base64 decoding wrapped key: {e}"))
///             })?;
///             let master_key = self.get_key(master_key_identifier)?;
///             let aad = master_key_identifier.as_bytes();
///             let nonce = ring::aead::Nonce::try_assume_unique_for_key(&wrapped_key[..NONCE_LEN])?;
///
///             let mut plaintext = Vec::with_capacity(wrapped_key.len() - NONCE_LEN);
///             plaintext.extend_from_slice(&wrapped_key[NONCE_LEN..]);
///
///             master_key.open_in_place(nonce, Aad::from(aad), &mut plaintext)?;
///             plaintext.resize(plaintext.len() - master_key.algorithm().tag_len(), 0u8);
///
///             Ok(plaintext)
///         }
///     }
///
/// #     Ok(())
/// # }
/// ```

#[async_trait::async_trait]
pub trait AsyncKmsClient: Send + Sync {
    /// Wrap encryption key bytes using the KMS with the specified master key
    async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String>;

    /// Unwrap a wrapped encryption key using the KMS with the specified master key
    async fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>>;
}

/// A reference-counted reference to a generic [`AsyncKmsClient`]
pub type AsyncKmsClientRef = Arc<dyn AsyncKmsClient>;

/// Trait for factories that create asynchronous KMS clients
#[async_trait::async_trait]
pub trait AsyncKmsClientFactory: Send + Sync {
    /// Create a new [`AsyncKmsClient`] instance using the provided configuration
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<AsyncKmsClientRef>;
}

#[async_trait::async_trait]
impl<T> AsyncKmsClientFactory for Arc<T>
where
    T: AsyncKmsClientFactory,
{
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<AsyncKmsClientRef> {
        self.deref().create_client(kms_connection_config).await
    }
}

#[async_trait::async_trait]
impl<T> AsyncKmsClientFactory for T
where
    T: Fn(&KmsConnectionConfig) -> BoxFuture<Result<AsyncKmsClientRef>> + Send + Sync + 'static,
{
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<AsyncKmsClientRef> {
        self(kms_connection_config).await
    }
}
