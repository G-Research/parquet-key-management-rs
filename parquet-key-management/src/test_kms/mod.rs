//! A KMS client implementation for use in tests, which is compatible
//! with the C++ Arrow LocalWrapKmsClient and records details of
//! KMS interactions.

#[cfg(feature = "async")]
mod async_impl;

use crate::errors::{Error, Result};
use crate::kms::{KmsClient, KmsClientFactory, KmsClientRef, KmsConnectionInfo};
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

/// Factory for building [`TestKmsClient`] instances
pub struct TestKmsClientFactory {
    key_map: HashMap<String, Vec<u8>>,
    invocations: Mutex<Vec<KmsConnectionInfo>>,
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
    pub fn invocations(&self) -> Vec<KmsConnectionInfo> {
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
    fn create_client(&self, kms_connection_info: &KmsConnectionInfo) -> Result<KmsClientRef> {
        self.invocations
            .lock()
            .unwrap()
            .push(kms_connection_info.clone());
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
