//! The key-management tools API for building file encryption and decryption properties
//! that work with a Key Management Server.

use crate::key_unwrapper::KeyUnwrapper;
use crate::key_wrapper::KeyWrapper;
use crate::kms::{KmsClientFactory, KmsConnectionConfig};
use crate::kms_manager::KmsManager;
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::{ParquetError, Result};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for encrypting a Parquet file using a KMS
#[derive(Debug)]
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
                        return Err(ParquetError::General(format!(
                            "Invalid encryption configuration. \
                            Column '{col_name}' is repeated multiple times for master key id \
                            '{master_key_id}'"
                        )));
                    }
                    Some(prev_id) => {
                        return Err(ParquetError::General(format!(
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
#[derive(Debug)]
pub struct DecryptionConfiguration {
    cache_lifetime: Option<Duration>,
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
}

impl Default for DecryptionConfiguration {
    fn default() -> Self {
        DecryptionConfigurationBuilder::default().build()
    }
}

/// Builder for a Parquet [`DecryptionConfiguration`].
pub struct DecryptionConfigurationBuilder {
    cache_lifetime: Option<Duration>,
}

impl DecryptionConfigurationBuilder {
    /// Create a new [`DecryptionConfigurationBuilder`] with default options
    pub fn new() -> Self {
        Self {
            cache_lifetime: Some(Duration::from_secs(600)),
        }
    }

    /// Finalizes the decryption configuration to be used
    pub fn build(self) -> DecryptionConfiguration {
        DecryptionConfiguration {
            cache_lifetime: self.cache_lifetime,
        }
    }

    /// Set how long to cache objects for, including decrypted key encryption keys
    /// and KMS clients. When None, objects are cached indefinitely.
    pub fn set_cache_lifetime(mut self, cache_lifetime: Option<Duration>) -> Self {
        self.cache_lifetime = cache_lifetime;
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
/// ```no_run
/// # use std::sync::Arc;
/// # use parquet_key_management::crypto_factory::{CryptoFactory, EncryptionConfiguration};
/// # use parquet_key_management::kms::KmsConnectionConfig;
/// # let crypto_factory: CryptoFactory = todo!();
/// let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let encryption_config = EncryptionConfiguration::builder("master_key_id".into()).build()?;
/// let encryption_properties = crypto_factory.file_encryption_properties(
///     kms_connection_config, &encryption_config)?;
/// # Ok::<(), parquet::errors::ParquetError>(())
/// ```
///
/// And file decryption properties can be constructed for reading an encrypted file:
/// ```no_run
/// # use std::sync::Arc;
/// # use parquet_key_management::crypto_factory::{CryptoFactory, DecryptionConfiguration};
/// # use parquet_key_management::kms::KmsConnectionConfig;
/// # let crypto_factory: CryptoFactory = todo!();
/// # let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let decryption_config = DecryptionConfiguration::default();
/// let decryption_properties = crypto_factory.file_decryption_properties(
///     kms_connection_config, decryption_config)?;
/// # Ok::<(), parquet::errors::ParquetError>(())
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
    pub fn file_decryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        decryption_configuration: DecryptionConfiguration,
    ) -> Result<FileDecryptionProperties> {
        let key_retriever = Arc::new(KeyUnwrapper::new(
            self.kms_manager.clone(),
            kms_connection_config,
            decryption_configuration,
        ));
        FileDecryptionProperties::with_key_retriever(key_retriever).build()
    }

    /// Create file encryption properties for a Parquet file
    pub fn file_encryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        encryption_configuration: &EncryptionConfiguration,
    ) -> Result<FileEncryptionProperties> {
        if !encryption_configuration.internal_key_material {
            return Err(ParquetError::NYI(
                "External key material is not yet implemented".to_owned(),
            ));
        }
        if encryption_configuration.data_key_length_bits != 128 {
            return Err(ParquetError::NYI(
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

        let mut builder = FileEncryptionProperties::builder(footer_key.key)
            .with_footer_key_metadata(footer_key.metadata)
            .with_plaintext_footer(encryption_configuration.plaintext_footer);

        for (master_key_id, column_paths) in &encryption_configuration.column_key_ids {
            for column_path in column_paths {
                let column_key = self.generate_key(master_key_id, false, &mut key_wrapper)?;
                builder = builder.with_column_key_and_metadata(
                    column_path,
                    column_key.key,
                    column_key.metadata,
                );
            }
        }

        builder.build()
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
    use crate::key_material::KeyMaterialBuilder;
    use crate::test_kms::{KmsConnectionConfigDetails, TestKmsClientFactory};
    use parquet::data_type::AsBytes;

    #[test]
    fn test_file_decryption_properties() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = Default::default();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config, config)
            .unwrap();

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

        let dek = decryption_props
            .footer_key(Some(serialized_key_material.as_bytes()))
            .unwrap()
            .into_owned();

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
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config.clone(), config)
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

        assert_eq!(0, kms_factory.invocations().len());

        decryption_props
            .footer_key(Some(serialized_footer_key_material.as_bytes()))
            .unwrap()
            .into_owned();
        assert_eq!(vec![default_config.clone()], kms_factory.invocations());

        decryption_props
            .column_key("x", Some(serialized_key_material.as_bytes()))
            .unwrap()
            .into_owned();
        // Same client should have been reused
        assert_eq!(vec![default_config.clone()], kms_factory.invocations());

        kms_config.refresh_key_access_token("super_secret".to_owned());

        decryption_props
            .column_key("x", Some(serialized_key_material.as_bytes()))
            .unwrap()
            .into_owned();
        // New key access token should have been used
        assert_eq!(
            vec![default_config.clone(), refreshed_config.clone()],
            kms_factory.invocations()
        );

        decryption_props
            .column_key("x", Some(serialized_key_material.as_bytes()))
            .unwrap()
            .into_owned();
        assert_eq!(
            vec![default_config, refreshed_config],
            kms_factory.invocations()
        );
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
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config.clone(), config)
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
            decryption_props
                .footer_key(Some(serialized_key_material.as_bytes()))
                .unwrap()
                .into_owned();
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
    fn test_uniform_encryption_properties() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let (column_names, column_keys, _) = file_encryption_properties.column_keys();
        assert!(column_names.is_empty());
        assert!(column_keys.is_empty());
    }

    #[test]
    fn test_round_trip_double_wrapping_properties() {
        round_trip_encryption_properties(true);
    }

    #[test]
    fn test_round_trip_single_wrapping_properties() {
        round_trip_encryption_properties(false);
    }

    fn round_trip_encryption_properties(double_wrapping: bool) {
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

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let decryption_properties = crypto_factory
            .file_decryption_properties(kms_config.clone(), Default::default())
            .unwrap();

        assert!(file_encryption_properties.encrypt_footer());
        assert!(file_encryption_properties.aad_prefix().is_none());
        assert_eq!(16, file_encryption_properties.footer_key().len());

        let retrieved_footer_key = decryption_properties
            .footer_key(
                file_encryption_properties
                    .footer_key_metadata()
                    .map(|k| k.as_bytes()),
            )
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
                .column_key(column_name, Some(key_metadata))
                .unwrap();
            assert_eq!(column_key, retrieved_key.as_slice());
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

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let footer_key_metadata = file_encryption_properties.footer_key_metadata().cloned();

        // Key-encryption keys are cached for the lifetime of file decryption properties,
        // and when creating new file decryption properties, a previous key-encryption key cache
        // may be reused if the cache lifetime hasn't expired and the KMS access token is the same.

        let get_new_decryption_properties = || {
            let decryption_config = DecryptionConfiguration::builder()
                .set_cache_lifetime(Some(Duration::from_secs(600)))
                .build();
            crypto_factory
                .file_decryption_properties(kms_config.clone(), decryption_config)
                .unwrap()
        };

        let retrieve_key = |props: &FileDecryptionProperties| {
            props.footer_key(footer_key_metadata.as_deref()).unwrap();
        };

        assert_eq!(0, kms_factory.keys_unwrapped());

        {
            let props = get_new_decryption_properties();
            retrieve_key(&props);
            time_controller.advance(Duration::from_secs(599));
            retrieve_key(&props);
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);
        }
        {
            let props = get_new_decryption_properties();
            retrieve_key(&props);
            assert_eq!(1, kms_factory.keys_unwrapped());
            time_controller.advance(Duration::from_secs(1));
            retrieve_key(&props);
            // Cache lifetime has expired but the key unwrapper still holds the
            // key encryption key cache.
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);
        }
        {
            let props = get_new_decryption_properties();
            retrieve_key(&props);
            // Newly created decryption properties use a new key encryption key cache
            assert_eq!(2, kms_factory.keys_unwrapped());
            // Old KEKs have been removed from the cache
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);
        }
        {
            time_controller.advance(Duration::from_secs(599));
            // Creating new decryption properties should re-use the more recent cache
            let props1 = get_new_decryption_properties();
            retrieve_key(&props1);
            assert_eq!(2, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().num_kek_read_caches);

            kms_config.refresh_key_access_token("new_secret".to_owned());
            // Creating decryption properties with a different access key should require
            // creating a new key encryption key cache.
            let props2 = get_new_decryption_properties();
            retrieve_key(&props2);
            assert_eq!(3, kms_factory.keys_unwrapped());
            // KEKs for old access token are still cached as they haven't expired
            assert_eq!(2, crypto_factory.cache_stats().num_kek_read_caches);

            // But the cache used by older file encryption properties is still usable.
            retrieve_key(&props1);
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

        let generate_encryption_props = || {
            let _ = crypto_factory
                .file_encryption_properties(kms_config.clone(), &encryption_config)
                .unwrap();
        };

        assert_eq!(0, kms_factory.keys_wrapped());

        generate_encryption_props();
        // We generate 1 KEK for each master key used and wrap it with the KMS
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_props();
        // KEK cache hasn't yet expired, we reused it to generate new props
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        time_controller.advance(Duration::from_secs(1));
        generate_encryption_props();
        // The KEK cache has now expired, so we generated 3 new KEKs and wrapped them with the KMS
        assert_eq!(6, kms_factory.keys_wrapped());
        // Old KEKs have been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().num_kek_write_caches);

        // Refreshing the access token should invalidate the KEK write cache,
        // requiring us to again generate new KEKs and wrap them with the KMS
        kms_config.refresh_key_access_token("new_secret".to_owned());
        generate_encryption_props();
        assert_eq!(9, kms_factory.keys_wrapped());
        // KEKs for old access token are still cached as they haven't expired
        assert_eq!(2, crypto_factory.cache_stats().num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_props();
        // The KEK cache for the refreshed token is still valid, no new KEKs were generated
        assert_eq!(9, kms_factory.keys_wrapped());
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

        let details = get_kms_connection_config_for_decryption(decryption_kms_config);

        assert_eq!(details.kms_instance_id, "456");
        assert_eq!(details.kms_instance_url, "https://example.com/kms2/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    #[test]
    fn test_get_kms_client_using_config_from_file() {
        // When KMS config doesn't have the instance ID and URL,
        // they should be retrieved from the file metadata.
        // Other properties like the access key and custom configuration can only be provided
        // at decryption time.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        let details = get_kms_connection_config_for_decryption(decryption_kms_config);

        assert_eq!(details.kms_instance_id, "123");
        assert_eq!(details.kms_instance_url, "https://example.com/kms1/");
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
                .unwrap()
        };

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let decryption_kms_config = Arc::new(decryption_kms_config);
        let decryption_properties = crypto_factory
            .file_decryption_properties(decryption_kms_config, Default::default())
            .unwrap();

        let _ = decryption_properties
            .footer_key(
                file_encryption_properties
                    .footer_key_metadata()
                    .map(|k| k.as_bytes()),
            )
            .unwrap();

        let mut invocations = kms_factory.invocations();
        assert_eq!(invocations.len(), 1);
        invocations.pop().unwrap()
    }
}
