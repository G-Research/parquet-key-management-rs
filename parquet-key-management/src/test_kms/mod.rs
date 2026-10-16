//! A KMS client implementation for use in tests, which is compatible
//! with the C++ Arrow LocalWrapKmsClient and records details of
//! KMS interactions.

#[cfg(feature = "async")]
mod async_impl;

use crate::errors::{Error, Result};
use crate::kms::{KmsClient, KmsClientFactory, KmsClientRef, KmsConnectionConfig};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "async")]
pub use async_impl::TestAsyncKmsClientFactory;

/// The test KMS client implementation
pub struct TestKmsClient {
    key_map: HashMap<String, Vec<u8>>,
    keys_wrapped: Arc<AtomicUsize>,
    keys_unwrapped: Arc<AtomicUsize>,
}

/// Properties from [`KmsConnectionConfig`] used to construct a KMS client
#[derive(Clone, Debug, PartialEq)]
pub struct KmsConnectionConfigDetails {
    /// The KMS instance id
    pub kms_instance_id: String,
    /// The KMS instance URL
    pub kms_instance_url: String,
    /// The KMS key access token
    pub key_access_token: String,
    /// Arbitrary KMS configuration options
    pub custom_kms_conf: HashMap<String, String>,
}

/// Factory for building [`TestKmsClient`] instances
pub struct TestKmsClientFactory {
    key_map: HashMap<String, Vec<u8>>,
    invocations: Mutex<Vec<KmsConnectionConfigDetails>>,
    keys_wrapped: Arc<AtomicUsize>,
    keys_unwrapped: Arc<AtomicUsize>,
}

impl TestKmsClientFactory {
    /// Create a new KMS client factory that uses the default "kf", "kc1" and "kc2" keys
    /// conventionally used in tests.
    pub fn with_default_keys() -> Self {
        let mut key_map = HashMap::default();
        key_map.insert("kf".to_owned(), "0123456789012345".as_bytes().to_vec());
        key_map.insert("kc1".to_owned(), "1234567890123450".as_bytes().to_vec());
        key_map.insert("kc2".to_owned(), "1234567890123451".as_bytes().to_vec());

        Self {
            key_map,
            invocations: Mutex::new(Vec::new()),
            keys_wrapped: Arc::new(AtomicUsize::new(0)),
            keys_unwrapped: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the configuration details used to create clients.
    /// Provided for unit testing
    pub fn invocations(&self) -> Vec<KmsConnectionConfigDetails> {
        self.invocations.lock().unwrap().clone()
    }

    /// Get the number of times a key was wrapped with a KMS client created by this factory
    pub fn keys_wrapped(&self) -> usize {
        self.keys_wrapped.load(Ordering::Relaxed)
    }

    /// Get the number of times a key was unwrapped with a KMS client created by this factory
    pub fn keys_unwrapped(&self) -> usize {
        self.keys_unwrapped.load(Ordering::Relaxed)
    }
}

impl KmsClientFactory for TestKmsClientFactory {
    fn create_client(&self, kms_connection_config: &KmsConnectionConfig) -> Result<KmsClientRef> {
        {
            let details = KmsConnectionConfigDetails {
                kms_instance_id: kms_connection_config.kms_instance_id().to_owned(),
                kms_instance_url: kms_connection_config.kms_instance_url().to_owned(),
                key_access_token: kms_connection_config.key_access_token(),
                custom_kms_conf: kms_connection_config.custom_kms_conf().clone(),
            };
            let mut invocations = self.invocations.lock().unwrap();
            invocations.push(details);
        }
        Ok(Arc::new(TestKmsClient::new(
            self.key_map.clone(),
            self.keys_wrapped.clone(),
            self.keys_unwrapped.clone(),
        )))
    }
}

impl TestKmsClient {
    /// Create a new [`TestKmsClient`]
    fn new(
        key_map: HashMap<String, Vec<u8>>,
        keys_wrapped: Arc<AtomicUsize>,
        keys_unwrapped: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            key_map,
            keys_wrapped,
            keys_unwrapped,
        }
    }

    fn get_key(&self, master_key_identifier: &str) -> Result<&[u8]> {
        let key = self.key_map.get(master_key_identifier).ok_or_else(|| {
            Error::General(format!("Invalid master key '{master_key_identifier}'"))
        })?;
        Ok(key)
    }
}

impl KmsClient for TestKmsClient {
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
        let master_key = self.get_key(master_key_identifier)?;
        let aad = master_key_identifier.as_bytes();
        let encoded = crate::key_encryption::encrypt_encryption_key(key_bytes, aad, master_key)?;
        self.keys_wrapped.fetch_add(1, Ordering::Relaxed);
        Ok(encoded)
    }

    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>> {
        let master_key = self.get_key(master_key_identifier)?;
        let aad = master_key_identifier.as_bytes();
        let plaintext =
            crate::key_encryption::decrypt_encryption_key(wrapped_key, aad, master_key)?;
        self.keys_unwrapped.fetch_add(1, Ordering::Relaxed);
        Ok(plaintext)
    }
}
