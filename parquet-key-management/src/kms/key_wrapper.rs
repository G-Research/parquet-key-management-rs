use crate::config::EncryptionConfiguration;
use crate::key_encryption::encrypt_encryption_key;
use crate::key_material::KeyMaterialBuilder;
use crate::kms::kms_manager::{KekWriteCache, KeyEncryptionKey, KmsManager};
use crate::kms::KmsConnectionConfig;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use parquet::errors::Result;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;

/// Creates key material for data encryption keys
pub(crate) struct KeyWrapper<'a> {
    kms_manager: &'a Arc<KmsManager>,
    kms_connection_config: Arc<KmsConnectionConfig>,
    encryption_configuration: &'a EncryptionConfiguration,
    master_key_to_kek: KekWriteCache,
}

impl<'a> KeyWrapper<'a> {
    pub fn new(
        kms_manager: &'a Arc<KmsManager>,
        kms_connection_config: Arc<KmsConnectionConfig>,
        encryption_configuration: &'a EncryptionConfiguration,
    ) -> Self {
        let master_key_to_kek = kms_manager.get_kek_write_cache(
            &kms_connection_config,
            encryption_configuration.cache_lifetime(),
        );
        Self {
            kms_manager,
            kms_connection_config,
            encryption_configuration,
            master_key_to_kek,
        }
    }

    pub fn get_key_metadata(
        &mut self,
        key: &[u8],
        master_key_id: &str,
        is_footer_key: bool,
    ) -> Result<Vec<u8>> {
        let key_material_builder = if is_footer_key {
            let kms_config = &self.kms_connection_config;
            // If instance ID or URL weren't provided, set them to non-empty default values
            let mut kms_instance_id = kms_config.kms_instance_id().to_owned();
            if kms_instance_id.is_empty() {
                kms_instance_id.push_str("DEFAULT");
            }
            let mut kms_instance_url = kms_config.kms_instance_url().to_owned();
            if kms_instance_url.is_empty() {
                kms_instance_url.push_str("DEFAULT");
            }
            KeyMaterialBuilder::for_footer_key(kms_instance_id, kms_instance_url)
        } else {
            KeyMaterialBuilder::for_column_key()
        };

        let key_material = if self.encryption_configuration.double_wrapping() {
            let mut master_key_to_kek = self.master_key_to_kek.lock().unwrap();
            let kek = match master_key_to_kek.entry(master_key_id.to_owned()) {
                Entry::Occupied(kek) => kek.into_mut(),
                Entry::Vacant(entry) => entry.insert(generate_key_encryption_key(
                    master_key_id,
                    self.kms_manager,
                    &self.kms_connection_config,
                    self.encryption_configuration.cache_lifetime(),
                )?),
            };

            let wrapped_dek = encrypt_encryption_key(key, &kek.key_id, &kek.key)?;

            key_material_builder
                .with_double_wrapped_key(
                    master_key_id.to_owned(),
                    kek.encoded_key_id.clone(),
                    kek.wrapped_key.clone(),
                    wrapped_dek,
                )
                .build()?
        } else {
            let kms_client = self.kms_manager.get_client(
                &self.kms_connection_config,
                self.encryption_configuration.cache_lifetime(),
            )?;
            let wrapped = kms_client.wrap_key(key, master_key_id)?;
            key_material_builder
                .with_single_wrapped_key(master_key_id.to_owned(), wrapped)
                .build()?
        };

        let serialized_material = key_material.serialize()?;

        Ok(serialized_material.into_bytes())
    }
}

fn generate_key_encryption_key(
    master_key_id: &str,
    kms_manager: &Arc<KmsManager>,
    kms_connection_config: &Arc<KmsConnectionConfig>,
    cache_lifetime: Option<Duration>,
) -> Result<KeyEncryptionKey> {
    let rng = SystemRandom::new();

    let mut key = vec![0u8; 16];
    rng.fill(&mut key)?;

    // Key ids should be globally unique to allow caching decrypted keys during reading
    let mut key_id = vec![0u8; 16];
    rng.fill(&mut key_id)?;

    let encoded_key_id = BASE64_STANDARD.encode(&key_id);

    let kms_client = kms_manager.get_client(kms_connection_config, cache_lifetime)?;
    let wrapped_key = kms_client.wrap_key(&key, master_key_id)?;

    Ok(KeyEncryptionKey {
        key_id,
        encoded_key_id,
        key,
        wrapped_key,
    })
}
