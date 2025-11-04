use crate::kms::{AsyncKmsClient, KmsClientRef};
use parquet::errors::Result;

/// An asynchronous KMS client implementation wrapping a synchronous one
pub(crate) struct WrappingAsyncKmsClient {
    inner: KmsClientRef,
}

impl WrappingAsyncKmsClient {
    /// Create a new [`WrappingAsyncKmsClient`] wrapping the provided [`KmsClientRef`]
    pub(crate) fn new(inner: KmsClientRef) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl AsyncKmsClient for WrappingAsyncKmsClient {
    async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
        self.inner.wrap_key(key_bytes, master_key_identifier)
    }

    async fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>> {
        self.inner.unwrap_key(wrapped_key, master_key_identifier)
    }
}
