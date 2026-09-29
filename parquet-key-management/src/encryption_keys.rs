//! Library-agnostic representation of keys for encrypting a Parquet file

#[cfg(feature = "parquet")]
use parquet::encryption::encrypt::{EncryptionPropertiesBuilder, FileEncryptionProperties};
use std::fmt;

/// A data encryption key along with its serialized key metadata,
/// which can later be used to retrieve the key when decrypting.
pub struct EncryptionKey {
    key: Vec<u8>,
    metadata: Vec<u8>,
}

impl EncryptionKey {
    pub(crate) fn new(key: Vec<u8>, metadata: Vec<u8>) -> Self {
        Self { key, metadata }
    }

    /// The plaintext data encryption key bytes
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The metadata for the encryption key
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Consume this key and return the key bytes and key metadata
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.key, self.metadata)
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("key", &"<redacted>")
            .field("metadata", &String::from_utf8_lossy(&self.metadata))
            .finish()
    }
}

/// Keys and settings required to encrypt a Parquet file
#[derive(Debug)]
pub struct FileEncryptionKeys {
    footer_key: EncryptionKey,
    plaintext_footer: bool,
    column_keys: Vec<(String, EncryptionKey)>,
}

impl FileEncryptionKeys {
    pub(crate) fn new(
        footer_key: EncryptionKey,
        plaintext_footer: bool,
        column_keys: Vec<(String, EncryptionKey)>,
    ) -> Self {
        Self {
            footer_key,
            plaintext_footer,
            column_keys,
        }
    }

    /// The key used to encrypt the file footer, and any columns without a column-specific key
    pub fn footer_key(&self) -> &EncryptionKey {
        &self.footer_key
    }

    /// Whether the footer should be written in plaintext rather than encrypted
    pub fn plaintext_footer(&self) -> bool {
        self.plaintext_footer
    }

    /// Column-specific encryption keys, as pairs of column path and key
    pub fn column_keys(&self) -> impl Iterator<Item = (&str, &EncryptionKey)> {
        self.column_keys
            .iter()
            .map(|(column_path, key)| (column_path.as_str(), key))
    }

    /// Convert into a builder for the `parquet` crate's [`FileEncryptionProperties`],
    /// which allows setting further options such as an AAD prefix before building.
    #[cfg(feature = "parquet")]
    pub fn into_parquet_builder(self) -> EncryptionPropertiesBuilder {
        let (footer_key, footer_key_metadata) = self.footer_key.into_parts();
        let mut builder = FileEncryptionProperties::builder(footer_key)
            .with_footer_key_metadata(footer_key_metadata)
            .with_plaintext_footer(self.plaintext_footer);
        for (column_path, column_key) in self.column_keys {
            let (key, metadata) = column_key.into_parts();
            builder = builder.with_column_key_and_metadata(&column_path, key, metadata);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto_factory::{CryptoFactory, DecryptionConfiguration, EncryptionConfiguration};
    use crate::test_kms::TestKmsClientFactory;
    use std::sync::Arc;

    #[test]
    fn test_debug_redacts_keys() {
        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let encryption_config = EncryptionConfiguration::builder("kf".into())
            .build()
            .unwrap();
        let keys = crypto_factory
            .file_encryption_keys(Arc::new(Default::default()), &encryption_config)
            .unwrap();

        let debug = format!("{keys:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&format!("{:?}", keys.footer_key().key())));
    }
}
