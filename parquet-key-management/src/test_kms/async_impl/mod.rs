mod wrap;

use crate::kms::{AsyncKmsClientFactory, AsyncKmsClientRef, KmsClientFactory, KmsConnectionConfig};
use crate::test_kms::async_impl::wrap::WrappingAsyncKmsClient;
use crate::test_kms::{KmsConnectionConfigDetails, TestKmsClientFactory};
use parquet::errors::Result;
use std::sync::Arc;

/// Factory for building asynchronous KMS client instances wrapping synchronous
/// [`TestKmsClient`](crate::test_kms::TestKmsClient) instances
pub struct TestAsyncKmsClientFactory {
    inner: Arc<TestKmsClientFactory>,
}

impl TestAsyncKmsClientFactory {
    /// Create a new KMS client factory that uses the default "kf", "kc1" and "kc2" keys
    /// conventionally used in tests.
    pub fn with_default_keys() -> Self {
        Self {
            inner: Arc::new(TestKmsClientFactory::with_default_keys()),
        }
    }

    /// Get the configuration details used to create clients.
    /// Provided for unit testing
    pub fn invocations(&self) -> Vec<KmsConnectionConfigDetails> {
        self.inner.invocations()
    }

    /// Get the number of times a key was wrapped with a KMS client created by this factory
    pub fn keys_wrapped(&self) -> usize {
        self.inner.keys_wrapped()
    }

    /// Get the number of times a key was unwrapped with a KMS client created by this factory
    pub fn keys_unwrapped(&self) -> usize {
        self.inner.keys_unwrapped()
    }
}

#[async_trait::async_trait]
impl AsyncKmsClientFactory for TestAsyncKmsClientFactory {
    async fn create_client(&self, config: &KmsConnectionConfig) -> Result<AsyncKmsClientRef> {
        Ok(Arc::new(WrappingAsyncKmsClient::new(
            self.inner.create_client(config)?,
        )))
    }
}
