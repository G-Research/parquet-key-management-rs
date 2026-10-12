//! The key-management tools API for building file encryption and decryption properties
//! that work with a Key Management Server.

use crate::encryption_keys::{EncryptionKey, FileEncryptionKeys};
use crate::errors::{Error, Result};
use crate::key_unwrapper::KeyUnwrapper;
use crate::key_wrapper::KeyWrapper;
#[cfg(feature = "async")]
use crate::kms::{reenter_async, AsyncKmsClientFactory, BridgeKmsClientFactory};
use crate::kms::{KmsClientFactory, KmsConnectionConfig};
use crate::kms_manager::KmsManager;
#[cfg(feature = "parquet")]
use parquet::encryption::decrypt::FileDecryptionProperties;
#[cfg(feature = "parquet")]
use parquet::encryption::encrypt::FileEncryptionProperties;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for encrypting a Parquet file using a KMS
#[derive(Clone, Debug)]
pub struct EncryptionConfiguration {
    footer_key_id: String,
    column_key_ids: HashMap<String, Vec<String>>,
    plaintext_footer: bool,
    double_wrapping: bool,
    cache_lifetime: Option<Duration>,
    internal_key_material: bool,
    data_key_length_bits: u32,
}

impl EncryptionConfiguration {
    /// Create a new builder for an [`EncryptionConfiguration`] using the specified
    /// master key identifier for footer encryption.
    pub fn builder(footer_key_id: String) -> EncryptionConfigurationBuilder {
        EncryptionConfigurationBuilder::new(footer_key_id)
    }

    /// Master key identifier for footer key encryption or signing
    pub fn footer_key_id(&self) -> &str {
        &self.footer_key_id
    }

    /// Map from master key identifiers to the names of columns encrypted with the key
    pub fn column_key_ids(&self) -> &HashMap<String, Vec<String>> {
        &self.column_key_ids
    }

    /// Whether to write the footer in plaintext.
    pub fn plaintext_footer(&self) -> bool {
        self.plaintext_footer
    }

    /// Whether to use double wrapping, where data encryption keys (DEKs) are wrapped
    /// with key encryption keys (KEKs), which are then wrapped with the KMS.
    /// This allows reducing interactions with the KMS.
    pub fn double_wrapping(&self) -> bool {
        self.double_wrapping
    }

    /// How long to cache objects for, including decrypted key encryption keys
    /// and KMS clients. When None, clients are cached indefinitely.
    pub fn cache_lifetime(&self) -> Option<Duration> {
        self.cache_lifetime
    }

    /// Whether to store encryption key material inside Parquet file metadata,
    /// rather than in external JSON files.
    /// Using external key material allows for re-wrapping of data keys after
    /// rotation of master keys in the KMS.
    /// Currently only internal key material is implemented.
    pub fn internal_key_material(&self) -> bool {
        self.internal_key_material
    }

    /// Number of bits for randomly generated data encryption keys.
    /// Currently only 128-bit keys are implemented.
    pub fn data_key_length_bits(&self) -> u32 {
        self.data_key_length_bits
    }
}

/// Builder for a Parquet [`EncryptionConfiguration`].
pub struct EncryptionConfigurationBuilder {
    footer_key_id: String,
    column_key_ids: HashMap<String, Vec<String>>,
    plaintext_footer: bool,
    double_wrapping: bool,
    cache_lifetime: Option<Duration>,
    internal_key_material: bool,
    data_key_length_bits: u32,
}

impl EncryptionConfigurationBuilder {
    /// Create a new [`EncryptionConfigurationBuilder`] using the specified master key
    /// identifier for footer encryption and default values for other options.
    pub fn new(footer_key_id: String) -> Self {
        Self {
            footer_key_id,
            column_key_ids: Default::default(),
            plaintext_footer: false,
            double_wrapping: true,
            cache_lifetime: Some(Duration::from_secs(600)),
            internal_key_material: true,
            data_key_length_bits: 128,
        }
    }

    /// Finalizes the encryption configuration to be used
    pub fn build(self) -> Result<EncryptionConfiguration> {
        let mut seen_columns = HashMap::new();
        for (master_key_id, columns) in self.column_key_ids.iter() {
            for col_name in columns.iter() {
                let prev_id = seen_columns.insert(col_name.clone(), master_key_id.clone());
                match prev_id {
                    Some(prev_id) if &prev_id == master_key_id => {
                        return Err(Error::General(format!(
                            "Invalid encryption configuration. \
                            Column '{col_name}' is repeated multiple times for master key id \
                            '{master_key_id}'"
                        )));
                    }
                    Some(prev_id) => {
                        return Err(Error::General(format!(
                            "Invalid encryption configuration. \
                            Column '{col_name}' is configured to use multiple master key ids: \
                            '{master_key_id}' and '{prev_id}'"
                        )));
                    }
                    None => {}
                }
            }
        }

        Ok(EncryptionConfiguration {
            footer_key_id: self.footer_key_id,
            column_key_ids: self.column_key_ids,
            plaintext_footer: self.plaintext_footer,
            double_wrapping: self.double_wrapping,
            cache_lifetime: self.cache_lifetime,
            internal_key_material: self.internal_key_material,
            data_key_length_bits: self.data_key_length_bits,
        })
    }

    /// Specify a column master key identifier and the column names to be encrypted with this key.
    /// Note that if no column keys are specified, uniform encryption is used where all columns
    /// are encrypted with the footer key.
    pub fn add_column_key(mut self, master_key_id: String, column_paths: Vec<String>) -> Self {
        self.column_key_ids
            .entry(master_key_id)
            .or_default()
            .extend(column_paths);
        self
    }

    /// Set whether to write the footer in plaintext.
    /// Defaults to false.
    pub fn set_plaintext_footer(mut self, plaintext_footer: bool) -> Self {
        self.plaintext_footer = plaintext_footer;
        self
    }

    /// Set whether to use double wrapping, where data encryption keys (DEKs) are wrapped
    /// with key encryption keys (KEKs), which are then wrapped with the KMS.
    /// This allows reducing interactions with the KMS.
    /// Defaults to True.
    pub fn set_double_wrapping(mut self, double_wrapping: bool) -> Self {
        self.double_wrapping = double_wrapping;
        self
    }

    /// Set how long to cache objects for, including decrypted key encryption keys
    /// and KMS clients. When None, clients are cached indefinitely.
    /// Defaults to 10 minutes.
    pub fn set_cache_lifetime(mut self, lifetime: Option<Duration>) -> Self {
        self.cache_lifetime = lifetime;
        self
    }
}

/// Configuration for decrypting a Parquet file using a KMS
#[derive(Clone, Debug)]
pub struct DecryptionConfiguration {
    cache_lifetime: Option<Duration>,
    read_kms_url: bool,
}

impl DecryptionConfiguration {
    /// Create a new builder for a [`DecryptionConfiguration`]
    pub fn builder() -> DecryptionConfigurationBuilder {
        DecryptionConfigurationBuilder::default()
    }

    /// How long to cache objects for, including decrypted key encryption keys
    /// and KMS clients. When None, objects are cached indefinitely.
    pub fn cache_lifetime(&self) -> Option<Duration> {
        self.cache_lifetime
    }

    /// Whether the KMS instance URL should be read from Parquet key material if it is
    /// not configured in the [`KmsConnectionConfig`].
    /// This should only be enabled when the KMS implementation validates the URL it
    /// receives, to ensure a KMS access token isn't sent to a malicious URL.
    pub fn read_kms_url(&self) -> bool {
        self.read_kms_url
    }
}

impl Default for DecryptionConfiguration {
    fn default() -> Self {
        DecryptionConfigurationBuilder::default().build()
    }
}

/// Builder for a Parquet [`DecryptionConfiguration`].
pub struct DecryptionConfigurationBuilder {
    cache_lifetime: Option<Duration>,
    read_kms_url: bool,
}

impl DecryptionConfigurationBuilder {
    /// Create a new [`DecryptionConfigurationBuilder`] with default options
    pub fn new() -> Self {
        Self {
            cache_lifetime: Some(Duration::from_secs(600)),
            read_kms_url: false,
        }
    }

    /// Finalizes the decryption configuration to be used
    pub fn build(self) -> DecryptionConfiguration {
        DecryptionConfiguration {
            cache_lifetime: self.cache_lifetime,
            read_kms_url: self.read_kms_url,
        }
    }

    /// Set how long to cache objects for, including decrypted key encryption keys
    /// and KMS clients. When None, objects are cached indefinitely.
    pub fn set_cache_lifetime(mut self, cache_lifetime: Option<Duration>) -> Self {
        self.cache_lifetime = cache_lifetime;
        self
    }

    /// Set whether the KMS instance URL should be read from Parquet key material if it is
    /// not configured in the [`KmsConnectionConfig`].
    /// This should only be enabled when the KMS implementation validates the URL it
    /// receives, to ensure a KMS access token isn't sent to a malicious URL.
    /// Defaults to false.
    pub fn set_read_kms_url(mut self, read_kms_url: bool) -> Self {
        self.read_kms_url = read_kms_url;
        self
    }
}

impl Default for DecryptionConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A factory that produces file decryption and encryption properties using
/// configuration options and a KMS client
///
/// Creating a `CryptoFactory` requires providing a [`KmsClientFactory`]
/// to create clients for your Key Management Server:
/// ```no_run
/// # use parquet_key_management::crypto_factory::CryptoFactory;
/// # use parquet_key_management::kms::KmsConnectionConfig;
/// # let kms_client_factory = |config: &KmsConnectionConfig| todo!();
/// let crypto_factory = CryptoFactory::new(kms_client_factory);
/// ```
///
/// The `CryptoFactory` can then be used to generate file encryption properties
/// when writing an encrypted Parquet file:
#[cfg_attr(feature = "parquet", doc = "```no_run")]
#[cfg_attr(not(feature = "parquet"), doc = "```ignore")]
/// # use std::sync::Arc;
/// # use parquet_key_management::crypto_factory::{CryptoFactory, EncryptionConfiguration};
/// # use parquet_key_management::kms::KmsConnectionConfig;
/// # let crypto_factory: CryptoFactory = todo!();
/// let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let encryption_config = EncryptionConfiguration::builder("master_key_id".into()).build()?;
/// let encryption_properties = crypto_factory.file_encryption_properties(
///     kms_connection_config, &encryption_config)?;
/// # Ok::<(), parquet_key_management::errors::Error>(())
/// ```
///
/// And file decryption properties can be constructed for reading an encrypted file:
#[cfg_attr(feature = "parquet", doc = "```no_run")]
#[cfg_attr(not(feature = "parquet"), doc = "```ignore")]
/// # use std::sync::Arc;
/// # use parquet_key_management::crypto_factory::{CryptoFactory, DecryptionConfiguration};
/// # use parquet_key_management::kms::KmsConnectionConfig;
/// # let crypto_factory: CryptoFactory = todo!();
/// # let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let decryption_config = DecryptionConfiguration::default();
/// let decryption_properties = crypto_factory.file_decryption_properties(
///     kms_connection_config, decryption_config)?;
/// # Ok::<(), parquet_key_management::errors::Error>(())
/// ```
///
/// A `CryptoFactory` can be reused multiple times to encrypt or decrypt many files,
/// but the same encryption properties should not be reused between different files.
///
/// The `KmsClientFactory` will be used to create KMS clients as required,
/// and these will be internally cached based on the KMS instance ID, KMS instance URL
/// and the key access token.
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

    /// Create a new [`CryptoFactory`], providing a [`ReenterAsync`](reenter_async::ReenterAsync) implementation and a factory
    /// function for creating asynchronous KMS clients.
    ///
    /// When using [`async-std`], consider using [`new_async_with_async_std`](CryptoFactory::new_async_with_async_std) instead.
    ///
    /// When using [`smol`], consider using [`new_async_with_smol`](CryptoFactory::new_async_with_smol) instead.
    ///
    /// When using [`tokio`], consider using [`new_async_with_tokio`](CryptoFactory::new_async_with_tokio) instead.
    ///
    /// [`async-std`]: https://docs.rs/async-std/latest/async_std/
    /// [`smol`]: https://docs.rs/smol/latest/smol/
    /// [`tokio`]: https://docs.rs/tokio/latest/tokio/
    #[cfg(feature = "async")]
    pub fn new_async<R, F>(reenter: R, kms_client_factory: F) -> Self
    where
        R: reenter_async::ReenterAsync,
        F: AsyncKmsClientFactory + 'static,
    {
        let bridge_factory = Arc::new(BridgeKmsClientFactory::new(
            reenter,
            Arc::new(kms_client_factory),
        ));
        CryptoFactory {
            kms_manager: Arc::new(KmsManager::new(bridge_factory)),
        }
    }

    /// Create a new [`CryptoFactory`], providing a factory function for creating asynchronous
    /// KMS clients. Use this when running inside an [`async-std`] runtime.
    ///
    /// [`async-std`]: https://docs.rs/async-std/latest/async_std/
    #[cfg(feature = "async-std")]
    pub fn new_async_with_async_std<T>(kms_client_factory: T) -> Self
    where
        T: AsyncKmsClientFactory + 'static,
    {
        Self::new_async(reenter_async::AsyncStdReenterAsync, kms_client_factory)
    }

    /// Create a new [`CryptoFactory`], providing a factory function for creating asynchronous
    /// KMS clients. Use this when running inside a [`smol`] runtime.
    ///
    /// [`smol`]: https://docs.rs/smol/latest/smol/
    #[cfg(feature = "smol")]
    pub fn new_async_with_smol<T>(kms_client_factory: T) -> Self
    where
        T: AsyncKmsClientFactory + 'static,
    {
        Self::new_async(reenter_async::SmolReenterAsync, kms_client_factory)
    }

    /// Create a new [`CryptoFactory`], providing a factory function for creating asynchronous
    /// KMS clients. Use this when running inside a [`tokio`] runtime.
    ///
    /// This implementation will panic if called outside of a Tokio runtime context or if the runtime
    /// is not multi-threaded.
    ///
    /// [`tokio`]: https://docs.rs/tokio/latest/tokio/
    #[cfg(feature = "tokio")]
    pub fn new_async_with_tokio<T>(kms_client_factory: T) -> Self
    where
        T: AsyncKmsClientFactory + 'static,
    {
        Self::new_async(reenter_async::TokioReenterAsync, kms_client_factory)
    }

    /// Get a KeyUnwrapper to use for reading a Parquet file
    pub fn key_unwrapper(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        decryption_configuration: DecryptionConfiguration,
    ) -> Result<KeyUnwrapper> {
        Ok(KeyUnwrapper::new(
            self.kms_manager.clone(),
            kms_connection_config,
            decryption_configuration,
        ))
    }

    /// Create file decryption properties for a Parquet file
    #[cfg(feature = "parquet")]
    pub fn file_decryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        decryption_configuration: DecryptionConfiguration,
    ) -> Result<Arc<FileDecryptionProperties>> {
        let key_retriever =
            Arc::new(self.key_unwrapper(kms_connection_config, decryption_configuration)?);
        Ok(FileDecryptionProperties::with_key_retriever(key_retriever).build()?)
    }

    /// Create file encryption properties for a Parquet file
    ///
    /// To set further encryption options not managed by the [`CryptoFactory`],
    /// use [`file_encryption_keys`](Self::file_encryption_keys) and
    /// [`FileEncryptionKeys::into_parquet_builder`] instead.
    #[cfg(feature = "parquet")]
    pub fn file_encryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        encryption_configuration: &EncryptionConfiguration,
    ) -> Result<Arc<FileEncryptionProperties>> {
        let encryption_keys =
            self.file_encryption_keys(kms_connection_config, encryption_configuration)?;
        Ok(encryption_keys.into_parquet_builder().build()?)
    }

    /// Generate the encryption keys and key metadata required to encrypt a Parquet file.
    pub fn file_encryption_keys(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        encryption_configuration: &EncryptionConfiguration,
    ) -> Result<FileEncryptionKeys> {
        if !encryption_configuration.internal_key_material {
            return Err(Error::NotYetImplemented(
                "External key material is not yet implemented".to_owned(),
            ));
        }
        if encryption_configuration.data_key_length_bits != 128 {
            return Err(Error::NotYetImplemented(
                "Only 128 bit data keys are currently implemented".to_owned(),
            ));
        }

        let mut key_wrapper = KeyWrapper::new(
            &self.kms_manager,
            kms_connection_config,
            encryption_configuration,
        );

        let footer_key = self.generate_key(
            encryption_configuration.footer_key_id(),
            true,
            &mut key_wrapper,
        )?;

        let mut column_keys = Vec::new();
        for (master_key_id, column_paths) in &encryption_configuration.column_key_ids {
            for column_path in column_paths {
                let column_key = self.generate_key(master_key_id, false, &mut key_wrapper)?;
                column_keys.push((column_path.clone(), column_key));
            }
        }

        Ok(FileEncryptionKeys::new(
            footer_key,
            encryption_configuration.plaintext_footer,
            column_keys,
        ))
    }

    fn generate_key(
        &self,
        master_key_identifier: &str,
        is_footer_key: bool,
        key_wrapper: &mut KeyWrapper,
    ) -> Result<EncryptionKey> {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 16];
        rng.fill(&mut key)?;

        let key_metadata =
            key_wrapper.get_key_metadata(&key, master_key_identifier, is_footer_key)?;

        Ok(EncryptionKey::new(key, key_metadata))
    }

    #[cfg(test)]
    pub(crate) fn cache_stats(&self) -> crate::kms_manager::CacheStats {
        self.kms_manager.cache_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_material::KeyMaterialBuilder;
    use crate::test_kms::{KmsConnectionConfigDetails, TestKmsClientFactory};

    #[test]
    fn test_key_unwrapper() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = Default::default();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let key_unwrapper = crypto_factory.key_unwrapper(kms_config, config).unwrap();

        let expected_dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .unwrap();

        let wrapped_key = kms.wrap_key(&expected_dek, "kc1").unwrap();
        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        let dek = key_unwrapper
            .unwrap_key(serialized_key_material.as_bytes())
            .unwrap();

        assert_eq!(dek, expected_dek);
    }

    #[test]
    fn test_kms_client_caching_with_lifetime() {
        test_kms_client_caching(Some(Duration::from_secs(6000)));
    }

    #[test]
    fn test_kms_client_caching_no_lifetime() {
        test_kms_client_caching(None);
    }

    fn test_kms_client_caching(cache_lifetime: Option<Duration>) {
        let _time_controller = crate::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = DecryptionConfiguration::builder()
            .set_cache_lifetime(cache_lifetime)
            .build();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        let key_unwrapper = crypto_factory
            .key_unwrapper(kms_config.clone(), config)
            .unwrap();

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .unwrap();

        let wrapped_key = kms.wrap_key(&dek, "kc1").unwrap();

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

        // Default config with ID set from the footer key material.
        // The URL isn't read from key material by default.
        let default_config = KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: "DEFAULT".to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        };

        // Expected config after the access token refresh
        let refreshed_config = KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: "DEFAULT".to_string(),
            key_access_token: "super_secret".to_string(),
            custom_kms_conf: Default::default(),
        };

        assert_eq!(0, kms_factory.invocations().len());

        key_unwrapper
            .unwrap_key(serialized_footer_key_material.as_bytes())
            .unwrap();
        assert_eq!(vec![default_config.clone()], kms_factory.invocations());

        key_unwrapper
            .unwrap_key(serialized_key_material.as_bytes())
            .unwrap();
        // Same client should have been reused
        assert_eq!(vec![default_config.clone()], kms_factory.invocations());

        kms_config.refresh_key_access_token("super_secret".to_owned());

        key_unwrapper
            .unwrap_key(serialized_key_material.as_bytes())
            .unwrap();
        // New key access token should have been used
        assert_eq!(
            vec![default_config.clone(), refreshed_config.clone()],
            kms_factory.invocations()
        );

        key_unwrapper
            .unwrap_key(serialized_key_material.as_bytes())
            .unwrap();
        assert_eq!(
            vec![default_config, refreshed_config],
            kms_factory.invocations()
        );
    }

    #[test]
    fn test_kms_client_caching_with_different_urls() {
        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        // The KMS config is updated from the footer key metadata per file,
        // so a separate key unwrapper is needed for each file
        let key_unwrapper = || {
            let config = DecryptionConfiguration::builder()
                .set_read_kms_url(true)
                .build();
            crypto_factory
                .key_unwrapper(Arc::new(KmsConnectionConfig::default()), config)
                .unwrap()
        };

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .unwrap();
        let wrapped_key = kms.wrap_key(&dek, "kc1").unwrap();

        let footer_key_material = |url: &str| {
            KeyMaterialBuilder::for_footer_key("123".to_owned(), url.to_owned())
                .with_single_wrapped_key("kc1".to_owned(), wrapped_key.clone())
                .build()
                .unwrap()
                .serialize()
                .unwrap()
        };
        let key_material_1 = footer_key_material("https://example.com/kms1/");
        let key_material_2 = footer_key_material("https://example.com/kms2/");

        let expected_config = |url: &str| KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: url.to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        };
        let expected_invocations = vec![
            expected_config("https://example.com/kms1/"),
            expected_config("https://example.com/kms2/"),
        ];

        key_unwrapper()
            .unwrap_key(key_material_1.as_bytes())
            .unwrap();
        key_unwrapper()
            .unwrap_key(key_material_2.as_bytes())
            .unwrap();
        // A new client should have been created for the second URL
        assert_eq!(expected_invocations, kms_factory.invocations());
        assert_eq!(2, crypto_factory.cache_stats().num_kms_clients);

        key_unwrapper()
            .unwrap_key(key_material_1.as_bytes())
            .unwrap();
        // The cached client for the first URL should be reused
        assert_eq!(expected_invocations, kms_factory.invocations());
    }

    #[test]
    fn test_kms_client_caching_with_default_instance() {
        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        // Instance ID and URL are not set, so default values are used
        let kms_config = Arc::new(KmsConnectionConfig::default());

        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(false)
            .build()
            .unwrap();
        let encryption_keys = crypto_factory
            .file_encryption_keys(kms_config.clone(), &encryption_config)
            .unwrap();

        let key_unwrapper = crypto_factory
            .key_unwrapper(kms_config, Default::default())
            .unwrap();
        let footer_key = key_unwrapper
            .unwrap_key(encryption_keys.footer_key().metadata())
            .unwrap();
        assert_eq!(encryption_keys.footer_key().key(), footer_key.as_slice());

        // The factory should only see "DEFAULT" values, and the client
        // created when writing should be reused when reading.
        let expected_invocations = vec![KmsConnectionConfigDetails {
            kms_instance_id: "DEFAULT".to_string(),
            kms_instance_url: "DEFAULT".to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        }];
        assert_eq!(expected_invocations, kms_factory.invocations());
        assert_eq!(1, crypto_factory.cache_stats().num_kms_clients);
    }

    #[test]
    fn test_kms_client_expiration() {
        let time_controller = crate::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = DecryptionConfiguration::builder()
            .set_cache_lifetime(Some(Duration::from_secs(600)))
            .build();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        let key_unwrapper = crypto_factory
            .key_unwrapper(kms_config.clone(), config)
            .unwrap();

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .unwrap();

        let wrapped_key = kms.wrap_key(&dek, "kc1").unwrap();
        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        assert_eq!(0, kms_factory.invocations().len());

        let do_key_retrieval = || {
            key_unwrapper
                .unwrap_key(serialized_key_material.as_bytes())
                .unwrap();
        };

        do_key_retrieval();
        assert_eq!(1, kms_factory.invocations().len());
        assert_eq!(1, crypto_factory.cache_stats().num_kms_clients);

        time_controller.advance(Duration::from_secs(599));

        do_key_retrieval();
        assert_eq!(1, kms_factory.invocations().len());
        assert_eq!(1, crypto_factory.cache_stats().num_kms_clients);

        time_controller.advance(Duration::from_secs(1));

        do_key_retrieval();
        assert_eq!(2, kms_factory.invocations().len());
        // The old KMS client is expired so has been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().num_kms_clients);

        time_controller.advance(Duration::from_secs(599));

        do_key_retrieval();
        assert_eq!(2, kms_factory.invocations().len());
        assert_eq!(1, crypto_factory.cache_stats().num_kms_clients);

        time_controller.advance(Duration::from_secs(1));

        do_key_retrieval();
        assert_eq!(3, kms_factory.invocations().len());
        assert_eq!(1, crypto_factory.cache_stats().num_kms_clients);
    }

    #[test]
    fn test_uniform_encryption_keys() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());

        let file_encryption_keys = crypto_factory
            .file_encryption_keys(kms_config.clone(), &encryption_config)
            .unwrap();

        assert_eq!(0, file_encryption_keys.column_keys().count());
    }

    #[test]
    fn test_round_trip_double_wrapping_keys() {
        round_trip_encryption_keys(true);
    }

    #[test]
    fn test_round_trip_single_wrapping_keys() {
        round_trip_encryption_keys(false);
    }

    fn round_trip_encryption_keys(double_wrapping: bool) {
        let _time_controller = crate::kms_manager::mock_time::time_controller();

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

        let file_encryption_keys = crypto_factory
            .file_encryption_keys(kms_config.clone(), &encryption_config)
            .unwrap();

        let key_unwrapper = crypto_factory
            .key_unwrapper(kms_config.clone(), Default::default())
            .unwrap();

        assert!(!file_encryption_keys.plaintext_footer());
        let footer_key = file_encryption_keys.footer_key();
        assert_eq!(16, footer_key.key().len());

        let retrieved_footer_key = key_unwrapper.unwrap_key(footer_key.metadata()).unwrap();
        assert_eq!(footer_key.key(), retrieved_footer_key.as_slice());

        let mut all_columns: Vec<&str> = file_encryption_keys
            .column_keys()
            .map(|(column_path, _)| column_path)
            .collect();
        all_columns.sort();
        assert_eq!(vec!["x0", "x1", "x2", "x3"], all_columns);
        for (_, column_key) in file_encryption_keys.column_keys() {
            assert_eq!(16, column_key.key().len());
            let retrieved_key = key_unwrapper.unwrap_key(column_key.metadata()).unwrap();
            assert_eq!(column_key.key(), retrieved_key.as_slice());
        }

        assert_eq!(1, kms_factory.invocations().len());
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
    #[test]
    fn test_decryption_key_encryption_key_caching() {
        let time_controller = crate::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let file_encryption_keys = crypto_factory
            .file_encryption_keys(kms_config.clone(), &encryption_config)
            .unwrap();

        let footer_key_metadata = file_encryption_keys.footer_key().metadata().to_vec();

        // Key-encryption keys are cached for the lifetime of a key unwrapper,
        // and when creating a new key unwrapper, a previous key-encryption key cache
        // may be reused if the cache lifetime hasn't expired and the KMS access token is the same.

        let get_new_key_unwrapper = || {
            let decryption_config = DecryptionConfiguration::builder()
                .set_cache_lifetime(Some(Duration::from_secs(600)))
                .build();
            crypto_factory
                .key_unwrapper(kms_config.clone(), decryption_config)
                .unwrap()
        };

        let retrieve_key = |key_unwrapper: &KeyUnwrapper| {
            key_unwrapper.unwrap_key(&footer_key_metadata).unwrap();
        };

        assert_eq!(0, kms_factory.keys_unwrapped());

        {
            let key_unwrapper = get_new_key_unwrapper();
            retrieve_key(&key_unwrapper);
            time_controller.advance(Duration::from_secs(599));
            retrieve_key(&key_unwrapper);
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);
        }
        {
            let key_unwrapper = get_new_key_unwrapper();
            retrieve_key(&key_unwrapper);
            assert_eq!(1, kms_factory.keys_unwrapped());
            time_controller.advance(Duration::from_secs(1));
            retrieve_key(&key_unwrapper);
            // Cache lifetime has expired but the key unwrapper still holds the
            // key encryption key cache.
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);
        }
        {
            let key_unwrapper = get_new_key_unwrapper();
            retrieve_key(&key_unwrapper);
            // Newly created key unwrappers use a new key encryption key cache
            assert_eq!(2, kms_factory.keys_unwrapped());
            // Old KEKs have been removed from the cache
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);
        }
        {
            time_controller.advance(Duration::from_secs(599));
            // Creating a new key unwrapper should re-use the more recent cache
            let key_unwrapper1 = get_new_key_unwrapper();
            retrieve_key(&key_unwrapper1);
            assert_eq!(2, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);

            kms_config.refresh_key_access_token("new_secret".to_owned());
            // Creating a key unwrapper with a different access key should require
            // creating a new key encryption key cache.
            let key_unwrapper2 = get_new_key_unwrapper();
            retrieve_key(&key_unwrapper2);
            assert_eq!(3, kms_factory.keys_unwrapped());
            // KEKs for old access token are still cached as they haven't expired
            assert_eq!(2, crypto_factory.cache_stats().num_kek_read_caches);

            // But the cache used by the older key unwrapper is still usable.
            retrieve_key(&key_unwrapper1);
            assert_eq!(3, kms_factory.keys_unwrapped());
        }
    }

    /// Test caching of key encryption keys when encrypting files
    #[test]
    fn test_encryption_key_encryption_key_caching() {
        let time_controller = crate::kms_manager::mock_time::time_controller();

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

        let generate_encryption_keys = || {
            let _ = crypto_factory
                .file_encryption_keys(kms_config.clone(), &encryption_config)
                .unwrap();
        };

        assert_eq!(0, kms_factory.keys_wrapped());

        generate_encryption_keys();
        // We generate 1 KEK for each master key used and wrap it with the KMS
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_keys();
        // KEK cache hasn't yet expired, we reused it to generate new keys
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        time_controller.advance(Duration::from_secs(1));
        generate_encryption_keys();
        // The KEK cache has now expired, so we generated 3 new KEKs and wrapped them with the KMS
        assert_eq!(6, kms_factory.keys_wrapped());
        // Old KEKs have been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        // Refreshing the access token should invalidate the KEK write cache,
        // requiring us to again generate new KEKs and wrap them with the KMS
        kms_config.refresh_key_access_token("new_secret".to_owned());
        generate_encryption_keys();
        assert_eq!(9, kms_factory.keys_wrapped());
        // KEKs for old access token are still cached as they haven't expired
        assert_eq!(2, crypto_factory.cache_stats().num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_keys();
        // The KEK cache for the refreshed token is still valid, no new KEKs were generated
        assert_eq!(9, kms_factory.keys_wrapped());
        assert_eq!(2, crypto_factory.cache_stats().num_kek_write_caches);
    }

    /// KEKs wrapped by one KMS instance must not be reused when encrypting with another instance
    #[test]
    fn test_encryption_key_encryption_key_caching_with_different_urls() {
        let kms_config = |url: &str| {
            Arc::new(
                KmsConnectionConfig::builder()
                    .set_kms_instance_id("123".to_owned())
                    .set_kms_instance_url(url.to_owned())
                    .build(),
            )
        };
        let kms_config_1 = kms_config("https://example.com/kms1/");
        let kms_config_2 = kms_config("https://example.com/kms2/");
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let generate_encryption_keys = |kms_config: &Arc<KmsConnectionConfig>| {
            let _ = crypto_factory
                .file_encryption_keys(kms_config.clone(), &encryption_config)
                .unwrap();
        };

        generate_encryption_keys(&kms_config_1);
        assert_eq!(1, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        // A new KEK must be generated and wrapped by the second KMS instance
        generate_encryption_keys(&kms_config_2);
        assert_eq!(2, kms_factory.keys_wrapped());
        assert_eq!(2, crypto_factory.cache_stats().num_kek_write_caches);
        let expected_config = |url: &str| KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: url.to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        };
        assert_eq!(
            vec![
                expected_config("https://example.com/kms1/"),
                expected_config("https://example.com/kms2/"),
            ],
            kms_factory.invocations()
        );

        // Cached KEKs are reused for each instance
        generate_encryption_keys(&kms_config_1);
        generate_encryption_keys(&kms_config_2);
        assert_eq!(2, kms_factory.keys_wrapped());
        assert_eq!(2, crypto_factory.cache_stats().num_kek_write_caches);
    }

    #[test]
    fn test_get_kms_client_using_provided_config() {
        // Connection configuration options provided at read time should take precedence over
        // the KMS URL and ID in the footer key material.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_kms_instance_id("456".to_owned())
            .set_kms_instance_url("https://example.com/kms2/".to_owned())
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        // Enable reading the URL from key material to check the provided config takes precedence
        let decryption_config = DecryptionConfiguration::builder()
            .set_read_kms_url(true)
            .build();

        let details =
            get_kms_connection_config_for_decryption(decryption_kms_config, decryption_config);

        assert_eq!(details.kms_instance_id, "456");
        assert_eq!(details.kms_instance_url, "https://example.com/kms2/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    #[test]
    fn test_get_kms_client_using_config_from_file() {
        // When KMS config doesn't have the instance ID and URL,
        // they should be retrieved from the file metadata if reading the URL is enabled.
        // Other properties like the access key and custom configuration can only be provided
        // at decryption time.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();
        let decryption_config = DecryptionConfiguration::builder()
            .set_read_kms_url(true)
            .build();

        let details =
            get_kms_connection_config_for_decryption(decryption_kms_config, decryption_config);

        assert_eq!(details.kms_instance_id, "123");
        assert_eq!(details.kms_instance_url, "https://example.com/kms1/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    #[test]
    fn test_get_kms_client_without_reading_kms_url_from_file() {
        // By default, the KMS instance URL in the file metadata is ignored
        // and the default URL is used, but the instance ID is still read from the file.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        let details = get_kms_connection_config_for_decryption(
            decryption_kms_config,
            DecryptionConfiguration::default(),
        );

        assert_eq!(details.kms_instance_id, "123");
        assert_eq!(details.kms_instance_url, "DEFAULT");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    #[test]
    fn encryption_configuration_with_conflicting_column() {
        let builder = EncryptionConfigurationBuilder::new("kf".to_owned())
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x1".to_owned()]);

        let build_result = builder.build();
        assert!(build_result.is_err());
        let error_message = build_result.unwrap_err().to_string();
        assert!(error_message.contains("Invalid encryption configuration. Column 'x1' is configured to use multiple master key ids: "));
        assert!(error_message.contains("'kc1'"));
        assert!(error_message.contains("'kc2'"));
    }

    #[test]
    fn encryption_configuration_with_repeated_column() {
        let builder = EncryptionConfigurationBuilder::new("kf".to_owned()).add_column_key(
            "kc1".to_owned(),
            vec!["x0".to_owned(), "x1".to_owned(), "x1".to_owned()],
        );

        let build_result = builder.build();
        assert!(build_result.is_err());
        let error_message = build_result.unwrap_err().to_string();
        assert!(error_message.contains("Invalid encryption configuration. Column 'x1' is repeated multiple times for master key id 'kc1'"));
    }

    fn get_kms_connection_config_for_decryption(
        decryption_kms_config: KmsConnectionConfig,
        decryption_config: DecryptionConfiguration,
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

        let file_encryption_keys = {
            let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
            let crypto_factory = CryptoFactory::new(kms_factory.clone());

            crypto_factory
                .file_encryption_keys(encryption_kms_config, &encryption_config)
                .unwrap()
        };

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let decryption_kms_config = Arc::new(decryption_kms_config);
        let key_unwrapper = crypto_factory
            .key_unwrapper(decryption_kms_config, decryption_config)
            .unwrap();

        let _ = key_unwrapper
            .unwrap_key(file_encryption_keys.footer_key().metadata())
            .unwrap();

        let mut invocations = kms_factory.invocations();
        assert_eq!(invocations.len(), 1);
        invocations.pop().unwrap()
    }
}
