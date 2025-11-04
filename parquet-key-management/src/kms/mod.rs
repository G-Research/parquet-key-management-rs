//! Types for integrating with a Key Management Server to use with Parquet Modular Encryption

#[cfg(feature = "async")]
mod async_impl;

use parquet::errors::Result;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock, RwLockReadGuard};

#[cfg(feature = "async")]
pub(crate) use async_impl::bridge::BridgeKmsClientFactory;
#[cfg(feature = "async")]
pub use async_impl::{reenter_async, AsyncKmsClient, AsyncKmsClientFactory, AsyncKmsClientRef};

/// API for interacting with a KMS.
/// This should be implemented by user code for integration with your KMS.
pub trait KmsClient: Send + Sync {
    /// Wrap encryption key bytes using the KMS with the specified master key
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String>;

    /// Unwrap a wrapped encryption key using the KMS with the specified master key
    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>>;
}

/// A reference-counted reference to a generic [`KmsClient`]
pub type KmsClientRef = Arc<dyn KmsClient>;

/// Holds configuration options required to connect to a KMS
#[derive(Clone, Debug)]
pub struct KmsConnectionConfig {
    kms_instance_url: String,
    kms_instance_id: String,
    key_access_token: Arc<RwLock<String>>,
    custom_kms_conf: HashMap<String, String>,
}

impl KmsConnectionConfig {
    /// Create a builder for a [`KmsConnectionConfig`]
    pub fn builder() -> KmsConnectionConfigBuilder {
        KmsConnectionConfigBuilder::default()
    }

    /// ID of the KMS instance to use for encryption,
    /// if multiple instances are available.
    pub fn kms_instance_id(&self) -> &str {
        &self.kms_instance_id
    }

    /// URL of the KMS instance to use for encryption.
    pub fn kms_instance_url(&self) -> &str {
        &self.kms_instance_url
    }

    /// The access token to pass to the KMS.
    pub fn key_access_token(&self) -> String {
        self.key_access_token.read().unwrap().clone()
    }

    /// Return the key access token inside a read lock.
    pub(crate) fn read_key_access_token(&self) -> RwLockReadGuard<'_, String> {
        self.key_access_token.read().unwrap()
    }

    /// Any KMS specific configuration options
    pub fn custom_kms_conf(&self) -> &HashMap<String, String> {
        &self.custom_kms_conf
    }

    /// Update the access token to be passed to the KMS.
    /// This method is provided to support KMSs that use an access token that can expire.
    /// Refreshing the access token will cause new KMS client instances to be created when needed
    /// rather than using previously cached clients that have an old access token.
    pub fn refresh_key_access_token(&self, key_access_token: String) {
        let mut token = self.key_access_token.write().unwrap();
        *token = key_access_token;
    }

    /// Modify the KMS instance ID to use
    pub(crate) fn set_kms_instance_id(&mut self, kms_instance_id: String) {
        self.kms_instance_id = kms_instance_id;
    }

    /// Modify the KMS instance URL to use
    pub(crate) fn set_kms_instance_url(&mut self, kms_instance_url: String) {
        self.kms_instance_url = kms_instance_url;
    }
}

impl Default for KmsConnectionConfig {
    fn default() -> Self {
        KmsConnectionConfigBuilder::default().build()
    }
}

/// A builder for creating a [`KmsConnectionConfig`]
pub struct KmsConnectionConfigBuilder {
    kms_instance_id: String,
    kms_instance_url: String,
    key_access_token: String,
    custom_kms_conf: HashMap<String, String>,
}

impl KmsConnectionConfigBuilder {
    /// Create a new [`KmsConnectionConfigBuilder`] with default options
    pub fn new() -> Self {
        Self {
            kms_instance_id: "".to_string(),
            kms_instance_url: "".to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        }
    }

    /// Finalizes the KMS connection configuration to be used
    pub fn build(self) -> KmsConnectionConfig {
        KmsConnectionConfig {
            kms_instance_id: self.kms_instance_id,
            kms_instance_url: self.kms_instance_url,
            key_access_token: Arc::new(RwLock::new(self.key_access_token)),
            custom_kms_conf: self.custom_kms_conf,
        }
    }

    /// Set the ID of the KMS instance to use for encryption
    pub fn set_kms_instance_id(mut self, kms_instance_id: String) -> Self {
        self.kms_instance_id = kms_instance_id;
        self
    }

    /// Set the URL of the KMS instance to use for encryption.
    pub fn set_kms_instance_url(mut self, kms_instance_url: String) -> Self {
        self.kms_instance_url = kms_instance_url;
        self
    }

    /// Set the authorization token to pass to the KMS.
    pub fn set_key_access_token(mut self, key_access_token: String) -> Self {
        self.key_access_token = key_access_token;
        self
    }

    /// Set all KMS specific configuration options
    pub fn set_custom_kms_conf(mut self, custom_conf: HashMap<String, String>) -> Self {
        self.custom_kms_conf = custom_conf;
        self
    }

    /// Set a KMS specific configuration option
    pub fn set_custom_kms_conf_option(mut self, conf_key: String, conf_value: String) -> Self {
        self.custom_kms_conf.insert(conf_key, conf_value);
        self
    }
}

impl Default for KmsConnectionConfigBuilder {
    /// Create a new [`KmsConnectionConfigBuilder`] with default options
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for factories that create KMS clients
pub trait KmsClientFactory: Send + Sync {
    /// Create a new [`KmsClient`] instance using the provided configuration
    fn create_client(&self, kms_connection_config: &KmsConnectionConfig) -> Result<KmsClientRef>;
}

impl<T> KmsClientFactory for Arc<T>
where
    T: KmsClientFactory,
{
    fn create_client(&self, kms_connection_config: &KmsConnectionConfig) -> Result<KmsClientRef> {
        self.deref().create_client(kms_connection_config)
    }
}

impl<T> KmsClientFactory for T
where
    T: Fn(&KmsConnectionConfig) -> Result<KmsClientRef> + Send + Sync + 'static,
{
    fn create_client(&self, kms_connection_config: &KmsConnectionConfig) -> Result<KmsClientRef> {
        self(kms_connection_config)
    }
}
