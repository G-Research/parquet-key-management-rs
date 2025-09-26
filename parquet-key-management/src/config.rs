use parquet::errors::{ParquetError, Result};
use std::collections::HashMap;
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
#[derive(Clone, Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
