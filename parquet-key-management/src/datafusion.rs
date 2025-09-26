//! Parquet Key Management Tools for DataFusion
//!
//! This module provides a DataFusion [`EncryptionFactory`] implementation based on the
//! Key Management Tools API, to enable integration with a KMS when reading and writing
//! encrypted Parquet with DataFusion.

use crate::async_crypto_factory::CryptoFactory;
use crate::async_kms::KmsConnectionConfig;
use crate::config::{DecryptionConfiguration, EncryptionConfiguration};
use datafusion_common::arrow::datatypes::SchemaRef;
use datafusion_common::config::{ConfigEntry, EncryptionFactoryOptions, ExtensionOptions};
use datafusion_common::encryption::{FileDecryptionProperties, FileEncryptionProperties};
use datafusion_common::{extensions_options, DataFusionError};
use datafusion_execution::parquet_encryption::EncryptionFactory;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Encryption factory for DataFusion that uses a `CryptoFactory` to integrate with a KMS.
pub struct KmsEncryptionFactory {
    crypto_factory: CryptoFactory,
    kms_connection_config: Arc<KmsConnectionConfig>,
}

impl KmsEncryptionFactory {
    /// Create a new [`KmsEncryptionFactory`] with the provided [`CryptoFactory`] and [`KmsConnectionConfig`].
    pub fn new(
        crypto_factory: CryptoFactory,
        kms_connection_config: Arc<KmsConnectionConfig>,
    ) -> Self {
        Self {
            crypto_factory,
            kms_connection_config,
        }
    }
}

#[async_trait::async_trait]
impl EncryptionFactory for KmsEncryptionFactory {
    async fn get_file_encryption_properties(
        &self,
        config: &EncryptionFactoryOptions,
        _schema: &SchemaRef,
        _file_path: &object_store::path::Path,
    ) -> datafusion_common::Result<Option<FileEncryptionProperties>> {
        let encryption_configuration = build_encryption_configuration(config)?;
        Ok(Some(
            self.crypto_factory
                .file_encryption_properties(
                    Arc::clone(&self.kms_connection_config),
                    &encryption_configuration,
                )
                .await?,
        ))
    }

    async fn get_file_decryption_properties(
        &self,
        config: &EncryptionFactoryOptions,
        _file_path: &object_store::path::Path,
    ) -> datafusion_common::Result<Option<FileDecryptionProperties>> {
        let decryption_configuration = build_decryption_configuration(config)?;
        Ok(Some(
            self.crypto_factory
                .file_decryption_properties(
                    Arc::clone(&self.kms_connection_config),
                    decryption_configuration,
                )
                .await?,
        ))
    }
}

impl std::fmt::Debug for KmsEncryptionFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsEncryptionFactory")
            .finish_non_exhaustive()
    }
}

/// DataFusion compatible options used to configure generation of encryption and decryption
/// properties for a Table when using a [`KmsEncryptionFactory`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KmsEncryptionFactoryOptions {
    /// The configuration to use when writing encrypted Parquet
    pub encryption: EncryptionOptions,
    /// The configuration to use when reading encrypted Parquet
    pub decryption: DecryptionOptions,
}

impl KmsEncryptionFactoryOptions {
    /// Create a new [`KmsEncryptionFactoryOptions `] from encryption and decryption configurations
    pub fn new(
        encryption_config: EncryptionConfiguration,
        decryption_config: DecryptionConfiguration,
    ) -> Self {
        Self {
            encryption: encryption_config.into(),
            decryption: decryption_config.into(),
        }
    }
}

extensions_options! {
    /// DataFusion compatible configuration options related to file encryption
    pub struct EncryptionOptions {
        /// Master key identifier for footer key encryption
        pub footer_key_id: String, default = "".to_owned()
        /// List of master key ids and the columns to be encrypted with each key,
        /// formatted like "columnKeyId1:column1,column2;columnKeyId2:column3"
        pub column_key_ids: String, default = "".to_owned()
        /// Whether to write footer metadata unencrypted
        pub plaintext_footer: bool, default = false
        /// Whether to encrypt data encryption keys with key encryption keys, before wrapping with the master key
        pub double_wrapping: bool, default = true
        /// How long in seconds to cache objects used during encryption
        pub cache_lifetime_s: Option<u64>, default = None
        /// Whether to store encryption key material inside Parquet files
        pub internal_key_material: bool, default = true
        /// Length of data encryption keys to generate
        pub data_key_length_bits: u64, default = 128
    }
}

extensions_options! {
    /// DataFusion compatible configuration options related to file decryption
    pub struct DecryptionOptions {
        /// How long in seconds to cache objects used during decryption
        pub cache_lifetime_s: Option<u64>, default = None
    }
}

// Manually implement PartialEq as using #[derive] isn't compatible with extensions_options macro
impl PartialEq for EncryptionOptions {
    fn eq(&self, other: &Self) -> bool {
        self.footer_key_id == other.footer_key_id
            && self.column_key_ids == other.column_key_ids
            && self.plaintext_footer == other.plaintext_footer
            && self.double_wrapping == other.double_wrapping
            && self.cache_lifetime_s == other.cache_lifetime_s
            && self.internal_key_material == other.internal_key_material
            && self.data_key_length_bits == other.data_key_length_bits
    }
}

impl PartialEq for DecryptionOptions {
    fn eq(&self, other: &Self) -> bool {
        self.cache_lifetime_s == other.cache_lifetime_s
    }
}

impl ExtensionOptions for KmsEncryptionFactoryOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn cloned(&self) -> Box<dyn ExtensionOptions> {
        Box::new(self.clone())
    }

    fn set(&mut self, key: &str, value: &str) -> datafusion_common::Result<()> {
        let (parent, key) = key.split_once('.').ok_or_else(|| {
            DataFusionError::Configuration(format!(
                "Invalid configuration key for KMS encryption: {key}"
            ))
        })?;
        match parent {
            "decryption" => ExtensionOptions::set(&mut self.decryption, key, value),
            "encryption" => ExtensionOptions::set(&mut self.encryption, key, value),
            _ => Err(DataFusionError::Configuration(format!(
                "Invalid configuration key for KMS encryption: {parent}"
            ))),
        }
    }

    fn entries(&self) -> Vec<ConfigEntry> {
        let mut decryption_entries = self.decryption.entries();
        for entry in decryption_entries.iter_mut() {
            entry.key = format!("decryption.{}", entry.key);
        }
        let mut encryption_entries = self.encryption.entries();
        for entry in encryption_entries.iter_mut() {
            entry.key = format!("encryption.{}", entry.key);
        }
        decryption_entries.append(&mut encryption_entries);
        decryption_entries
    }
}

impl From<EncryptionConfiguration> for EncryptionOptions {
    fn from(config: EncryptionConfiguration) -> Self {
        EncryptionOptions {
            footer_key_id: config.footer_key_id().to_owned(),
            column_key_ids: serialize_column_keys(config.column_key_ids()),
            plaintext_footer: config.plaintext_footer(),
            double_wrapping: config.double_wrapping(),
            cache_lifetime_s: config.cache_lifetime().map(|lifetime| lifetime.as_secs()),
            internal_key_material: config.internal_key_material(),
            data_key_length_bits: config.data_key_length_bits() as u64,
        }
    }
}

impl TryInto<EncryptionConfiguration> for EncryptionOptions {
    type Error = DataFusionError;

    fn try_into(self) -> Result<EncryptionConfiguration, Self::Error> {
        let mut builder = EncryptionConfiguration::builder(self.footer_key_id.clone())
            .set_double_wrapping(self.double_wrapping)
            .set_plaintext_footer(self.plaintext_footer)
            .set_cache_lifetime(self.cache_lifetime_s.map(Duration::from_secs));
        let column_keys = deserialize_column_keys(&self.column_key_ids)?;
        for (key, value) in column_keys.into_iter() {
            builder = builder.add_column_key(key, value);
        }
        Ok(builder.build()?)
    }
}

impl From<DecryptionConfiguration> for DecryptionOptions {
    fn from(config: DecryptionConfiguration) -> Self {
        DecryptionOptions {
            cache_lifetime_s: config.cache_lifetime().map(|lifetime| lifetime.as_secs()),
        }
    }
}

impl TryInto<DecryptionConfiguration> for DecryptionOptions {
    type Error = DataFusionError;

    fn try_into(self) -> Result<DecryptionConfiguration, Self::Error> {
        Ok(DecryptionConfiguration::builder()
            .set_cache_lifetime(self.cache_lifetime_s.map(Duration::from_secs))
            .build())
    }
}

fn serialize_column_keys(column_key_ids: &HashMap<String, Vec<String>>) -> String {
    let mut result = String::new();
    let mut first = true;
    for (key_id, columns) in column_key_ids.iter() {
        if !first {
            result.push(';');
        }
        result.push_str(key_id);
        result.push(':');
        result.push_str(&columns.join(","));
        first = false;
    }
    result
}

fn deserialize_column_keys(
    column_key_ids: &str,
) -> datafusion_common::Result<HashMap<String, Vec<String>>> {
    let mut keys = HashMap::new();
    for key_with_cols in column_key_ids.split(';') {
        if key_with_cols.is_empty() {
            continue;
        }
        let (key_id, cols) = key_with_cols.split_once(':').ok_or_else(|| {
            DataFusionError::Configuration(format!(
                "Invalid column_key_ids format in encryption configuration: '{column_key_ids}'"
            ))
        })?;
        let cols = cols
            .split(',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        keys.insert(key_id.to_owned(), cols);
    }
    Ok(keys)
}

fn build_decryption_configuration(
    options: &EncryptionFactoryOptions,
) -> datafusion_common::Result<DecryptionConfiguration> {
    let kms_options: KmsEncryptionFactoryOptions = options.to_extension_options()?;
    kms_options.decryption.try_into()
}

fn build_encryption_configuration(
    options: &EncryptionFactoryOptions,
) -> datafusion_common::Result<EncryptionConfiguration> {
    let kms_options: KmsEncryptionFactoryOptions = options.to_extension_options()?;
    kms_options.encryption.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion_common::config::ParquetEncryptionOptions;

    #[test]
    fn round_trip_column_key_ids() {
        let mut column_key_ids = HashMap::new();
        column_key_ids.insert("kc1".into(), vec!["x0".into(), "x2".into()]);
        column_key_ids.insert("kc2".into(), vec![]);
        column_key_ids.insert("kc3".into(), vec!["x3".into()]);

        let serialized = serialize_column_keys(&column_key_ids);

        let deserialized = deserialize_column_keys(&serialized).unwrap();

        assert_eq!(column_key_ids, deserialized);
    }

    #[test]
    fn round_trip_empty_column_key_ids() {
        let column_key_ids = HashMap::new();

        let serialized = serialize_column_keys(&column_key_ids);

        let deserialized = deserialize_column_keys(&serialized).unwrap();

        assert_eq!(deserialized.len(), 0);
    }

    #[test]
    fn default_encryption_options_to_config() {
        let options = KmsEncryptionFactoryOptions::default();
        let encryption_config: EncryptionConfiguration = options.encryption.try_into().unwrap();

        assert_eq!(encryption_config.footer_key_id(), "");
        assert!(encryption_config.column_key_ids().is_empty());
        assert!(encryption_config.double_wrapping());
        assert!(encryption_config.internal_key_material());
        assert!(!encryption_config.plaintext_footer());
        assert_eq!(encryption_config.data_key_length_bits(), 128);
        assert_eq!(encryption_config.cache_lifetime(), None);
    }

    #[test]
    fn default_decryption_options_to_config() {
        let options = KmsEncryptionFactoryOptions::default();

        let decryption_config: DecryptionConfiguration = options.decryption.try_into().unwrap();
        assert_eq!(decryption_config.cache_lifetime(), None);
    }

    #[test]
    fn round_trip_default_options_through_factory_options() {
        let options = KmsEncryptionFactoryOptions::default();
        let mut crypto_options = ParquetEncryptionOptions::default();
        crypto_options.configure_factory("test_factory", &options);
        let options_out: KmsEncryptionFactoryOptions = crypto_options
            .factory_options
            .to_extension_options()
            .unwrap();
        assert_eq!(options, options_out);
    }

    #[test]
    fn round_trip_built_config_through_factory_options() {
        let encryption_config = EncryptionConfiguration::builder("kf".to_owned())
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .set_cache_lifetime(Some(Duration::from_secs(300)))
            .set_plaintext_footer(true)
            .set_double_wrapping(false)
            .build()
            .unwrap();
        let decryption_config = DecryptionConfiguration::builder()
            .set_cache_lifetime(Some(Duration::from_secs(120)))
            .build();
        let options = KmsEncryptionFactoryOptions::new(encryption_config, decryption_config);

        let mut crypto_options = ParquetEncryptionOptions::default();
        crypto_options.configure_factory("test_factory", &options);
        let options_out: KmsEncryptionFactoryOptions = crypto_options
            .factory_options
            .to_extension_options()
            .unwrap();
        assert_eq!(options, options_out);

        let encryption_config_out: EncryptionConfiguration = options.encryption.try_into().unwrap();

        assert_eq!(encryption_config_out.footer_key_id(), "kf");
        assert_eq!(encryption_config_out.column_key_ids().len(), 1);
        assert_eq!(
            encryption_config_out.column_key_ids().get("kc1"),
            Some(&vec!["x0".to_owned(), "x1".to_owned()])
        );
        assert!(!encryption_config_out.double_wrapping());
        assert!(encryption_config_out.internal_key_material());
        assert!(encryption_config_out.plaintext_footer());
        assert_eq!(encryption_config_out.data_key_length_bits(), 128);
        assert_eq!(
            encryption_config_out.cache_lifetime(),
            Some(Duration::from_secs(300))
        );

        let decryption_config_out: DecryptionConfiguration = options.decryption.try_into().unwrap();

        assert_eq!(
            decryption_config_out.cache_lifetime(),
            Some(Duration::from_secs(120))
        );
    }
}
