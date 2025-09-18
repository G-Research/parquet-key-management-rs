//! The key-management tools `async` API for building file encryption and decryption properties
//! that work with a Key Management Server.
//!
//! # Example of writing then reading an encrypted Parquet file asynchronously
//! ```
//! use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
//! use base64::prelude::BASE64_STANDARD;
//! use base64::Engine;
//! use futures::future::BoxFuture;
//! use futures::{FutureExt, TryStreamExt};
//! use parquet::arrow::arrow_reader::ArrowReaderOptions;
//! use parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder;
//! use parquet::arrow::async_writer::AsyncArrowWriter;
//! use parquet::errors::{ParquetError, Result};
//! use parquet::file::properties::WriterProperties;
//! use parquet_key_management::async_crypto_factory::CryptoFactory;
//! use parquet_key_management::async_kms::{KmsClient, KmsClientRef, KmsConnectionConfig};
//! use parquet_key_management::config::{DecryptionConfiguration, EncryptionConfigurationBuilder};
//! use ring::aead::{Aad, LessSafeKey, UnboundKey, AES_128_GCM, NONCE_LEN};
//! use ring::rand::{SecureRandom, SystemRandom};
//! use std::collections::HashMap;
//! use std::sync::Arc;
//! use tempfile::TempDir;
//! use tokio::fs::File;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<()> {
//! let temp_dir = TempDir::new()?;
//! let file_path = temp_dir.path().join("encrypted_example.parquet");
//!
//! // Create a CryptoFactory, providing a factory function
//! // that will create an example KMS client
//! let crypto_factory = CryptoFactory::new(DemoKmsClient::create);
//!
//! // Specify any options required to connect to our KMS.
//! // These are ignored by the DemoKmsClient but shown here for illustration.
//! // The KMS instance ID and URL will be stored in the Parquet encryption metadata
//! // so don't need to be specified if you are only reading files.
//! let connection_config = Arc::new(
//!     KmsConnectionConfig::builder()
//!         .set_kms_instance_id("kms1".into())
//!         .set_kms_instance_url("https://example.com/kms".into())
//!         .set_key_access_token("secret_token".into())
//!         .set_custom_kms_conf_option("custom_option".into(), "some_value".into())
//!         .build(),
//! );
//!
//! // Create an encryption configuration that will encrypt the footer with the "kf" key,
//! // the "x" column with the "kc1" key, and the "y" column with the "kc2" key,
//! // while leaving the "id" column unencrypted.
//! let encryption_config = EncryptionConfigurationBuilder::new("kf".into())
//!     .add_column_key("kc1".into(), vec!["x".into()])
//!     .add_column_key("kc2".into(), vec!["y".into()])
//!     .build()?;
//!
//! // Use the CryptoFactory to generate file encryption properties using the configuration
//! let encryption_properties = crypto_factory
//!     .file_encryption_properties(connection_config.clone(), &encryption_config)
//!     .await?;
//! let writer_properties = WriterProperties::builder()
//!     .with_file_encryption_properties(encryption_properties)
//!     .build();
//!
//! // Write the encrypted Parquet file
//! {
//!     let file = File::create(&file_path).await?;
//!
//!     let ids = Int32Array::from(vec![0, 1, 2, 3, 4, 5]);
//!     let x_vals = Float32Array::from(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5]);
//!     let y_vals = Float32Array::from(vec![1.0, 1.1, 1.2, 1.3, 1.4, 1.5]);
//!     let batch = RecordBatch::try_from_iter(vec![
//!         ("id", Arc::new(ids) as ArrayRef),
//!         ("x", Arc::new(x_vals) as ArrayRef),
//!         ("y", Arc::new(y_vals) as ArrayRef),
//!     ])?;
//!
//!     let mut writer = AsyncArrowWriter::try_new(file, batch.schema(), Some(writer_properties))?;
//!
//!     writer.write(&batch).await?;
//!     writer.close().await?;
//! }
//!
//! // Use the CryptoFactory to generate file decryption properties.
//! // We don't need to specify which columns are encrypted and which keys are used,
//! // that information is stored in the file metadata.
//! let decryption_config = DecryptionConfiguration::default();
//! let decryption_properties = crypto_factory
//!     .file_decryption_properties(connection_config, decryption_config)
//!     .await?;
//! let reader_options =
//!     ArrowReaderOptions::new().with_file_decryption_properties(decryption_properties);
//!
//! // Read the file using the configured decryption properties
//! let file = File::open(&file_path).await?;
//!
//! let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, reader_options).await?;
//! let stream = builder.build()?;
//! let batches = stream.try_collect::<Vec<_>>().await?;
//! println!("Read batches: {batches:?}");
//!
//! /// Example KMS client that uses in-memory AES keys.
//! /// A real KMS client should interact with a Key Management Server to encrypt and decrypt keys.
//! pub struct DemoKmsClient {
//!     key_map: HashMap<String, Vec<u8>>,
//! }
//!
//! impl DemoKmsClient {
//!     pub fn create(_config: &KmsConnectionConfig) -> BoxFuture<'_, Result<KmsClientRef>> {
//!         async {
//!             let mut key_map = HashMap::default();
//!             key_map.insert("kf".into(), "0123456789012345".into());
//!             key_map.insert("kc1".into(), "1234567890123450".into());
//!             key_map.insert("kc2".into(), "1234567890123451".into());
//!
//!             Ok(Arc::new(Self { key_map }) as KmsClientRef)
//!         }
//!         .boxed()
//!     }
//!
//!     /// Get the AES key corresponding to a key identifier
//!     fn get_key(&self, master_key_identifier: &str) -> Result<LessSafeKey> {
//!         let key = self.key_map.get(master_key_identifier).ok_or_else(|| {
//!             ParquetError::General(format!("Invalid master key '{master_key_identifier}'"))
//!         })?;
//!         let key = UnboundKey::new(&AES_128_GCM, key)
//!             .map_err(|e| ParquetError::General(format!("Error creating AES key '{e}'")))?;
//!         Ok(LessSafeKey::new(key))
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl KmsClient for DemoKmsClient {
//!     /// Take a randomly generated key and encrypt it using the specified master key
//!     async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
//!         let master_key = self.get_key(master_key_identifier)?;
//!         let aad = master_key_identifier.as_bytes();
//!         let rng = SystemRandom::new();
//!
//!         let mut nonce = [0u8; NONCE_LEN];
//!         rng.fill(&mut nonce)?;
//!         let nonce = ring::aead::Nonce::assume_unique_for_key(nonce);
//!
//!         let tag_len = master_key.algorithm().tag_len();
//!         let mut ciphertext = Vec::with_capacity(NONCE_LEN + key_bytes.len() + tag_len);
//!         ciphertext.extend_from_slice(nonce.as_ref());
//!         ciphertext.extend_from_slice(key_bytes);
//!         let tag = master_key.seal_in_place_separate_tag(
//!             nonce,
//!             Aad::from(aad),
//!             &mut ciphertext[NONCE_LEN..],
//!         )?;
//!         ciphertext.extend_from_slice(tag.as_ref());
//!         let encoded = BASE64_STANDARD.encode(&ciphertext);
//!
//!         Ok(encoded)
//!     }
//!
//!     /// Take an encrypted key and decrypt it using the specified master key identifier
//!     async fn unwrap_key(
//!         &self,
//!         wrapped_key: &str,
//!         master_key_identifier: &str,
//!     ) -> Result<Vec<u8>> {
//!         let wrapped_key = BASE64_STANDARD.decode(wrapped_key).map_err(|e| {
//!             ParquetError::General(format!("Error base64 decoding wrapped key: {e}"))
//!         })?;
//!         let master_key = self.get_key(master_key_identifier)?;
//!         let aad = master_key_identifier.as_bytes();
//!         let nonce = ring::aead::Nonce::try_assume_unique_for_key(&wrapped_key[..NONCE_LEN])?;
//!
//!         let mut plaintext = Vec::with_capacity(wrapped_key.len() - NONCE_LEN);
//!         plaintext.extend_from_slice(&wrapped_key[NONCE_LEN..]);
//!
//!         master_key.open_in_place(nonce, Aad::from(aad), &mut plaintext)?;
//!         plaintext.resize(plaintext.len() - master_key.algorithm().tag_len(), 0u8);
//!
//!         Ok(plaintext)
//!     }
//! }
//!
//! # Ok(())
//! # }
//! ```

use crate::async_kms::key_unwrapper::KeyUnwrapper;
use crate::async_kms::key_wrapper::KeyWrapper;
use crate::async_kms::kms_manager::KmsManager;
use crate::async_kms::{KmsClientFactory, KmsConnectionConfig};
use crate::config::{DecryptionConfiguration, EncryptionConfiguration};
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::{ParquetError, Result};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;

/// A factory that produces file decryption and encryption properties using
/// configuration options and a KMS client
///
/// Creating a `CryptoFactory` requires providing a [`KmsClientFactory`]
/// to create clients for your Key Management Server:
/// ```no_run
/// # use futures::future::BoxFuture;
/// # use parquet::errors::Result;
/// # use parquet_key_management::async_crypto_factory::CryptoFactory;
/// # use parquet_key_management::async_kms::{KmsConnectionConfig, KmsClientRef};
/// # fn kms_client_factory(_: &KmsConnectionConfig) -> BoxFuture<'_, Result<KmsClientRef>> {
/// #     todo!()
/// # }
/// let crypto_factory = CryptoFactory::new(kms_client_factory);
/// ```
///
/// The `CryptoFactory` can then be used to generate file encryption properties
/// when writing an encrypted Parquet file:
/// ```no_run
/// # use std::sync::Arc;
/// # use parquet_key_management::config::EncryptionConfiguration;
/// # use parquet_key_management::async_crypto_factory::CryptoFactory;
/// # use parquet_key_management::async_kms::KmsConnectionConfig;
/// # futures::executor::block_on(async {
/// # let crypto_factory: CryptoFactory = todo!();
/// let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let encryption_config = EncryptionConfiguration::builder("master_key_id".into()).build()?;
/// let encryption_properties = crypto_factory.file_encryption_properties(
///     kms_connection_config, &encryption_config).await?;
/// # Ok::<(), parquet::errors::ParquetError>(())
/// # });
/// ```
///
/// And file decryption properties can be constructed for reading an encrypted file:
/// ```no_run
/// # use std::sync::Arc;
/// # use parquet_key_management::config::DecryptionConfiguration;
/// # use parquet_key_management::async_crypto_factory::CryptoFactory;
/// # use parquet_key_management::async_kms::KmsConnectionConfig;
/// # futures::executor::block_on(async {
/// # let crypto_factory: CryptoFactory = todo!();
/// # let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let decryption_config = DecryptionConfiguration::default();
/// let decryption_properties = crypto_factory.file_decryption_properties(
///     kms_connection_config, decryption_config).await?;
/// # Ok::<(), parquet::errors::ParquetError>(())
/// # });
/// ```
///
/// A `CryptoFactory` can be reused multiple times to encrypt or decrypt many files,
/// but the same encryption properties should not be reused between different files.
///
/// The `KmsClientFactory` will be used to create KMS clients as required,
/// and these will be internally cached based on the KMS instance ID and the key access token.
/// This means that if the key access token is changed using
/// [`KmsConnectionConfig::refresh_key_access_token`],
/// new `KmsClient` instances will be created using the new token rather than reusing
/// a cached client.
pub struct CryptoFactory {
    kms_manager: Arc<KmsManager>,
}

impl CryptoFactory {
    /// Create a new [`CryptoFactory`], providing a factory function for creating KMS clients
    pub fn new<T>(kms_client_factory: T) -> Self
    where
        T: KmsClientFactory + 'static,
    {
        CryptoFactory {
            kms_manager: Arc::new(KmsManager::new(kms_client_factory)),
        }
    }

    /// Create file decryption properties for a Parquet file
    pub async fn file_decryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        decryption_configuration: DecryptionConfiguration,
    ) -> Result<FileDecryptionProperties> {
        let key_retriever = Arc::new(
            KeyUnwrapper::new(
                self.kms_manager.clone(),
                kms_connection_config,
                decryption_configuration,
            )
            .await,
        );
        FileDecryptionProperties::with_async_key_retriever(key_retriever).build()
    }

    /// Create file encryption properties for a Parquet file
    pub async fn file_encryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        encryption_configuration: &EncryptionConfiguration,
    ) -> Result<FileEncryptionProperties> {
        if !encryption_configuration.internal_key_material() {
            return Err(ParquetError::NYI(
                "External key material is not yet implemented".to_owned(),
            ));
        }
        if encryption_configuration.data_key_length_bits() != 128 {
            return Err(ParquetError::NYI(
                "Only 128 bit data keys are currently implemented".to_owned(),
            ));
        }

        let mut key_wrapper = KeyWrapper::new(
            &self.kms_manager,
            kms_connection_config,
            encryption_configuration,
        )
        .await;

        let footer_key = self
            .generate_key(
                encryption_configuration.footer_key_id(),
                true,
                &mut key_wrapper,
            )
            .await?;

        let mut builder = FileEncryptionProperties::builder(footer_key.key)
            .with_footer_key_metadata(footer_key.metadata)
            .with_plaintext_footer(encryption_configuration.plaintext_footer());

        for (master_key_id, column_paths) in encryption_configuration.column_key_ids() {
            for column_path in column_paths {
                let column_key = self
                    .generate_key(master_key_id, false, &mut key_wrapper)
                    .await?;
                builder = builder.with_column_key_and_metadata(
                    column_path,
                    column_key.key,
                    column_key.metadata,
                );
            }
        }

        builder.build()
    }

    async fn generate_key(
        &self,
        master_key_identifier: &str,
        is_footer_key: bool,
        key_wrapper: &mut KeyWrapper<'_>,
    ) -> Result<EncryptionKey> {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 16];
        rng.fill(&mut key)?;

        let key_metadata = key_wrapper
            .get_key_metadata(&key, master_key_identifier, is_footer_key)
            .await?;

        Ok(EncryptionKey::new(key, key_metadata))
    }

    #[cfg(test)]
    pub(crate) async fn cache_stats(&self) -> crate::async_kms::kms_manager::CacheStats {
        self.kms_manager.cache_stats().await
    }
}

struct EncryptionKey {
    key: Vec<u8>,
    metadata: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(key: Vec<u8>, metadata: Vec<u8>) -> Self {
        Self { key, metadata }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_kms::test::{KmsConnectionConfigDetails, TestKmsClientFactory};
    use crate::config::EncryptionConfigurationBuilder;
    use crate::key_material::KeyMaterialBuilder;
    use parquet::data_type::AsBytes;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    async fn test_file_decryption_properties() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = Default::default();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config, config)
            .await
            .unwrap();

        let expected_dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .await
            .unwrap();

        let wrapped_key = kms.wrap_key(&expected_dek, "kc1").await.unwrap();
        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        let dek = decryption_props
            .footer_key_async(Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();

        assert_eq!(dek, expected_dek);
    }

    #[tokio::test]
    async fn test_kms_client_caching_with_lifetime() {
        test_kms_client_caching(Some(Duration::from_secs(6000))).await;
    }

    #[tokio::test]
    async fn test_kms_client_caching_no_lifetime() {
        test_kms_client_caching(None).await;
    }

    async fn test_kms_client_caching(cache_lifetime: Option<Duration>) {
        let _time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = DecryptionConfiguration::builder()
            .set_cache_lifetime(cache_lifetime)
            .build();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config.clone(), config)
            .await
            .unwrap();

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .await
            .unwrap();

        let wrapped_key = kms.wrap_key(&dek, "kc1").await.unwrap();

        let footer_key_material =
            KeyMaterialBuilder::for_footer_key("123".to_owned(), "https://example.com".to_owned())
                .with_single_wrapped_key("kc1".to_owned(), wrapped_key.clone())
                .build()
                .unwrap();
        let serialized_footer_key_material = footer_key_material.serialize().unwrap();

        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        // Default config with ID and URL set from the footer key material
        let default_config = KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: "https://example.com".to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        };

        // Expected config after the access token refresh
        let refreshed_config = KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: "https://example.com".to_string(),
            key_access_token: "super_secret".to_string(),
            custom_kms_conf: Default::default(),
        };

        assert_eq!(0, kms_factory.invocations().await.len());

        decryption_props
            .footer_key_async(Some(serialized_footer_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            vec![default_config.clone()],
            kms_factory.invocations().await
        );

        decryption_props
            .column_key_async("x", Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        // Same client should have been reused
        assert_eq!(
            vec![default_config.clone()],
            kms_factory.invocations().await
        );

        kms_config
            .refresh_key_access_token("super_secret".to_owned())
            .await;

        decryption_props
            .column_key_async("x", Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        // New key access token should have been used
        assert_eq!(
            vec![default_config.clone(), refreshed_config.clone()],
            kms_factory.invocations().await
        );

        decryption_props
            .column_key_async("x", Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            vec![default_config, refreshed_config],
            kms_factory.invocations().await
        );
    }

    #[tokio::test]
    async fn test_kms_client_expiration() {
        let time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = DecryptionConfiguration::builder()
            .set_cache_lifetime(Some(Duration::from_secs(600)))
            .build();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config.clone(), config)
            .await
            .unwrap();

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .await
            .unwrap();

        let wrapped_key = kms.wrap_key(&dek, "kc1").await.unwrap();
        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        assert_eq!(0, kms_factory.invocations().await.len());

        let do_key_retrieval = async || {
            decryption_props
                .footer_key_async(Some(serialized_key_material.as_bytes()))
                .await
                .unwrap()
                .into_owned();
        };

        do_key_retrieval().await;
        assert_eq!(1, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(599));

        do_key_retrieval().await;
        assert_eq!(1, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(1));

        do_key_retrieval().await;
        assert_eq!(2, kms_factory.invocations().await.len());
        // The old KMS client is expired so has been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(599));

        do_key_retrieval().await;
        assert_eq!(2, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(1));

        do_key_retrieval().await;
        assert_eq!(3, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);
    }

    #[tokio::test]
    async fn test_uniform_encryption_properties() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let (column_names, column_keys, _) = file_encryption_properties.column_keys();
        assert!(column_names.is_empty());
        assert!(column_keys.is_empty());
    }

    #[tokio::test]
    async fn test_round_trip_double_wrapping_properties() {
        round_trip_encryption_properties(true).await;
    }

    #[tokio::test]
    async fn test_round_trip_single_wrapping_properties() {
        round_trip_encryption_properties(false).await;
    }

    async fn round_trip_encryption_properties(double_wrapping: bool) {
        let _time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(
            KmsConnectionConfig::builder()
                .set_kms_instance_id("DEFAULT".to_owned())
                .build(),
        );
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(double_wrapping)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let decryption_properties = crypto_factory
            .file_decryption_properties(kms_config.clone(), Default::default())
            .await
            .unwrap();

        assert!(file_encryption_properties.encrypt_footer());
        assert!(file_encryption_properties.aad_prefix().is_none());
        assert_eq!(16, file_encryption_properties.footer_key().len());

        let retrieved_footer_key = decryption_properties
            .footer_key_async(
                file_encryption_properties
                    .footer_key_metadata()
                    .map(|k| k.as_bytes()),
            )
            .await
            .unwrap();
        assert_eq!(
            file_encryption_properties.footer_key(),
            retrieved_footer_key.as_slice()
        );

        let (column_names, column_keys, key_metadata) = file_encryption_properties.column_keys();
        let mut all_columns: Vec<String> = column_names.clone();
        all_columns.sort();
        assert_eq!(vec!["x0", "x1", "x2", "x3"], all_columns);
        for col_idx in 0..column_keys.len() {
            let column_name = &column_names[col_idx];
            let column_key = &column_keys[col_idx];
            let key_metadata = &key_metadata[col_idx];

            assert_eq!(16, column_key.len());
            let retrieved_key = decryption_properties
                .column_key_async(column_name, Some(key_metadata))
                .await
                .unwrap();
            assert_eq!(column_key, retrieved_key.as_slice());
        }

        assert_eq!(1, kms_factory.invocations().await.len());
        if double_wrapping {
            // With double wrapping, only need to wrap one KEK per master key id used
            assert_eq!(3, kms_factory.keys_wrapped());
            assert_eq!(3, kms_factory.keys_unwrapped());
        } else {
            // With single wrapping, need to wrap the footer key and a DEK per column
            assert_eq!(5, kms_factory.keys_wrapped());
            assert_eq!(5, kms_factory.keys_unwrapped());
        }
    }

    /// Test caching of key encryption keys when decrypting files
    #[tokio::test]
    async fn test_decryption_key_encryption_key_caching() {
        let time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let footer_key_metadata = file_encryption_properties.footer_key_metadata().cloned();

        // Key-encryption keys are cached for the lifetime of file decryption properties,
        // and when creating new file decryption properties, a previous key-encryption key cache
        // may be reused if the cache lifetime hasn't expired and the KMS access token is the same.

        let get_new_decryption_properties = async || {
            let decryption_config = DecryptionConfiguration::builder()
                .set_cache_lifetime(Some(Duration::from_secs(600)))
                .build();
            crypto_factory
                .file_decryption_properties(kms_config.clone(), decryption_config)
                .await
                .unwrap()
        };

        let retrieve_key = async |props: &FileDecryptionProperties| {
            props
                .footer_key_async(footer_key_metadata.as_deref())
                .await
                .unwrap();
        };

        assert_eq!(0, kms_factory.keys_unwrapped());

        {
            let props = get_new_decryption_properties().await;
            retrieve_key(&props).await;
            time_controller.advance(Duration::from_secs(599));
            retrieve_key(&props).await;
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);
        }
        {
            let props = get_new_decryption_properties().await;
            retrieve_key(&props).await;
            assert_eq!(1, kms_factory.keys_unwrapped());
            time_controller.advance(Duration::from_secs(1));
            retrieve_key(&props).await;
            // Cache lifetime has expired but the key unwrapper still holds the
            // key encryption key cache.
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);
        }
        {
            let props = get_new_decryption_properties().await;
            retrieve_key(&props).await;
            // Newly created decryption properties use a new key encryption key cache
            assert_eq!(2, kms_factory.keys_unwrapped());
            // Old KEKs have been removed from the cache
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);
        }
        {
            time_controller.advance(Duration::from_secs(599));
            // Creating new decryption properties should re-use the more recent cache
            let props1 = get_new_decryption_properties().await;
            retrieve_key(&props1).await;
            assert_eq!(2, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);

            kms_config
                .refresh_key_access_token("new_secret".to_owned())
                .await;
            // Creating decryption properties with a different access key should require
            // creating a new key encryption key cache.
            let props2 = get_new_decryption_properties().await;
            retrieve_key(&props2).await;
            assert_eq!(3, kms_factory.keys_unwrapped());
            // KEKs for old access token are still cached as they haven't expired
            assert_eq!(2, crypto_factory.cache_stats().await.num_kek_read_caches);

            // But the cache used by older file encryption properties is still usable.
            retrieve_key(&props1).await;
            assert_eq!(3, kms_factory.keys_unwrapped());
        }
    }

    /// Test caching of key encryption keys when encrypting files
    #[tokio::test]
    async fn test_encryption_key_encryption_key_caching() {
        let time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .set_cache_lifetime(Some(Duration::from_secs(600)))
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let generate_encryption_props = async || {
            let _ = crypto_factory
                .file_encryption_properties(kms_config.clone(), &encryption_config)
                .await
                .unwrap();
        };

        assert_eq!(0, kms_factory.keys_wrapped());

        generate_encryption_props().await;
        // We generate 1 KEK for each master key used and wrap it with the KMS
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_props().await;
        // KEK cache hasn't yet expired, we reused it to generate new props
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kek_write_caches);

        time_controller.advance(Duration::from_secs(1));
        generate_encryption_props().await;
        // The KEK cache has now expired, so we generated 3 new KEKs and wrapped them with the KMS
        assert_eq!(6, kms_factory.keys_wrapped());
        // Old KEKs have been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().await.num_kek_write_caches);

        // Refreshing the access token should invalidate the KEK write cache,
        // requiring us to again generate new KEKs and wrap them with the KMS
        kms_config
            .refresh_key_access_token("new_secret".to_owned())
            .await;
        generate_encryption_props().await;
        assert_eq!(9, kms_factory.keys_wrapped());
        // KEKs for old access token are still cached as they haven't expired
        assert_eq!(2, crypto_factory.cache_stats().await.num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_props().await;
        // The KEK cache for the refreshed token is still valid, no new KEKs were generated
        assert_eq!(9, kms_factory.keys_wrapped());
        assert_eq!(2, crypto_factory.cache_stats().await.num_kek_write_caches);
    }

    #[tokio::test]
    async fn test_get_kms_client_using_provided_config() {
        // Connection configuration options provided at read time should take precedence over
        // the KMS URL and ID in the footer key material.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_kms_instance_id("456".to_owned())
            .set_kms_instance_url("https://example.com/kms2/".to_owned())
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        let details = get_kms_connection_config_for_decryption(decryption_kms_config).await;

        assert_eq!(details.kms_instance_id, "456");
        assert_eq!(details.kms_instance_url, "https://example.com/kms2/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    #[tokio::test]
    async fn test_get_kms_client_using_config_from_file() {
        // When KMS config doesn't have the instance ID and URL,
        // they should be retrieved from the file metadata.
        // Other properties like the access key and custom configuration can only be provided
        // at decryption time.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        let details = get_kms_connection_config_for_decryption(decryption_kms_config).await;

        assert_eq!(details.kms_instance_id, "123");
        assert_eq!(details.kms_instance_url, "https://example.com/kms1/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    async fn get_kms_connection_config_for_decryption(
        decryption_kms_config: KmsConnectionConfig,
    ) -> KmsConnectionConfigDetails {
        let encryption_kms_config = Arc::new(
            KmsConnectionConfig::builder()
                .set_kms_instance_id("123".to_owned())
                .set_kms_instance_url("https://example.com/kms1/".to_owned())
                .set_key_access_token("secret_1".to_owned())
                .set_custom_kms_conf_option("test_key".to_owned(), "test_value_1".to_owned())
                .build(),
        );

        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let file_encryption_properties = {
            let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
            let crypto_factory = CryptoFactory::new(kms_factory.clone());

            crypto_factory
                .file_encryption_properties(encryption_kms_config, &encryption_config)
                .await
                .unwrap()
        };

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let decryption_kms_config = Arc::new(decryption_kms_config);
        let decryption_properties = crypto_factory
            .file_decryption_properties(decryption_kms_config, Default::default())
            .await
            .unwrap();

        let _ = decryption_properties
            .footer_key_async(
                file_encryption_properties
                    .footer_key_metadata()
                    .map(|k| k.as_bytes()),
            )
            .await
            .unwrap();

        let mut invocations = kms_factory.invocations().await;
        assert_eq!(invocations.len(), 1);
        invocations.pop().unwrap()
    }
}
