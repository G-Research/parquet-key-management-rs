use crate::config::DecryptionConfiguration;
use crate::key_encryption;
use crate::key_material::KeyMaterial;
use crate::kms::kms_manager::{KekReadCache, KmsManager};
use crate::kms::KmsConnectionConfig;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use parquet::encryption::decrypt::KeyRetriever;
use parquet::errors::{ParquetError, Result};
use std::collections::hash_map::Entry;
use std::sync::{Arc, RwLock};

/// Unwraps (decrypts) key encryption keys and data encryption keys using a KMS
pub(crate) struct KeyUnwrapper {
    kms_manager: Arc<KmsManager>,
    kms_connection_config: RwLock<Arc<KmsConnectionConfig>>,
    decryption_configuration: DecryptionConfiguration,
    kek_cache: KekReadCache,
}

impl KeyUnwrapper {
    pub fn new(
        kms_manager: Arc<KmsManager>,
        kms_connection_config: Arc<KmsConnectionConfig>,
        decryption_configuration: DecryptionConfiguration,
    ) -> Self {
        let kek_cache = kms_manager.get_kek_read_cache(
            &kms_connection_config,
            decryption_configuration.cache_lifetime(),
        );
        let kms_connection_config = RwLock::new(kms_connection_config);
        KeyUnwrapper {
            kms_manager,
            kms_connection_config,
            decryption_configuration,
            kek_cache,
        }
    }

    fn unwrap_single_wrapped_key(&self, wrapped_dek: &str, master_key_id: &str) -> Result<Vec<u8>> {
        let kms_connection_config = self.kms_connection_config.read().unwrap();
        let client = self.kms_manager.get_client(
            &kms_connection_config,
            self.decryption_configuration.cache_lifetime(),
        )?;
        client.unwrap_key(wrapped_dek, master_key_id)
    }

    fn unwrap_double_wrapped_key(
        &self,
        wrapped_dek: &str,
        master_key_id: &str,
        kek_id: &str,
        wrapped_kek: &str,
    ) -> Result<Vec<u8>> {
        let mut kek_cache = self.kek_cache.lock().unwrap();
        let kek = match kek_cache.entry(kek_id.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let kms_connection_config = self.kms_connection_config.read().unwrap();
                let client = self.kms_manager.get_client(
                    &kms_connection_config,
                    self.decryption_configuration.cache_lifetime(),
                )?;
                let kek = client.unwrap_key(wrapped_kek, master_key_id)?;
                entry.insert(kek)
            }
        };
        let decoded_kek_id = BASE64_STANDARD.decode(kek_id).map_err(|e| {
            ParquetError::General(format!(
                "Could not base64 decode key encryption key id: {e}"
            ))
        })?;
        key_encryption::decrypt_encryption_key(wrapped_dek, &decoded_kek_id, kek)
    }

    /// If the KMS instance ID or URL weren't provided in the connection configuration,
    /// try to read them from the footer key metadata.
    /// When a configuration value is present in both the file metadata and connection configuration,
    /// the value from the connection configuration takes precedence.
    fn update_kms_config_from_footer_metadata(
        &self,
        kms_instance_id: &str,
        kms_instance_url: &str,
    ) -> Result<()> {
        let mut kms_connection_config = self.kms_connection_config.write().unwrap();

        if !kms_connection_config.kms_instance_id().is_empty()
            && !kms_connection_config.kms_instance_url().is_empty()
        {
            return Ok(());
        }

        let mut_config = Arc::make_mut(&mut kms_connection_config);
        if mut_config.kms_instance_id().is_empty() {
            if kms_instance_id.is_empty() {
                return Err(ParquetError::General(
                    "KMS instance ID not set in connection configuration or footer key metadata"
                        .to_owned(),
                ));
            }
            mut_config.set_kms_instance_id(kms_instance_id.to_owned());
        }

        if mut_config.kms_instance_url().is_empty() {
            if kms_instance_url.is_empty() {
                return Err(ParquetError::General(
                    "KMS instance URL not set in connection configuration or footer key metadata"
                        .to_owned(),
                ));
            }
            mut_config.set_kms_instance_url(kms_instance_url.to_owned());
        }

        Ok(())
    }
}

impl KeyRetriever for KeyUnwrapper {
    fn retrieve_key(&self, key_metadata: &[u8]) -> Result<Vec<u8>> {
        let key_material = std::str::from_utf8(key_metadata)?;
        let key_material = KeyMaterial::deserialize(key_material)?;
        if !key_material.internal_storage {
            return Err(ParquetError::NYI(
                "Decryption using external key material is not yet implemented".to_owned(),
            ));
        }

        // If unwrapping a footer key, optionally set the KMS instance ID and URL
        if let (Some(instance_id), Some(instance_url)) = (
            &key_material.kms_instance_id,
            &key_material.kms_instance_url,
        ) {
            self.update_kms_config_from_footer_metadata(instance_id, instance_url)?;
        }

        if key_material.double_wrapping {
            if let (Some(kek_id), Some(wrapped_kek)) =
                (key_material.key_encryption_key_id, key_material.wrapped_kek)
            {
                self.unwrap_double_wrapped_key(
                    &key_material.wrapped_dek,
                    &key_material.master_key_id,
                    &kek_id,
                    &wrapped_kek,
                )
            } else {
                Err(ParquetError::General(
                    "Key uses double wrapping but key encryption key is not set".to_owned(),
                ))
            }
        } else {
            self.unwrap_single_wrapped_key(&key_material.wrapped_dek, &key_material.master_key_id)
        }
    }
}
