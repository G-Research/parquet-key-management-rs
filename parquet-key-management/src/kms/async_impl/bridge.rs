use crate::kms::{
    reenter_async::ReenterAsync, AsyncKmsClientFactory, AsyncKmsClientRef, KmsClient,
    KmsClientFactory, KmsClientRef,
};
use parquet::errors::Result;
use std::sync::Arc;

/// [`KmsClient`] implementation that bridges to an asynchronous
/// [`AsyncKmsClient`](crate::kms::AsyncKmsClient) using a [`ReenterAsync`] implementation
struct BridgeKmsClient<R: ReenterAsync> {
    reenter: R,
    inner: AsyncKmsClientRef,
}

impl<R: ReenterAsync> BridgeKmsClient<R> {
    /// Create a new [`BridgeKmsClient`] using the provided [`ReenterAsync`] implementation
    /// and asynchronous KMS client.
    fn new(reenter: R, inner: AsyncKmsClientRef) -> BridgeKmsClient<R> {
        BridgeKmsClient { reenter, inner }
    }
}

impl<R: ReenterAsync> KmsClient for BridgeKmsClient<R> {
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
        self.reenter
            .reenter(async { self.inner.wrap_key(key_bytes, master_key_identifier).await })
    }

    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>> {
        self.reenter.reenter(async {
            self.inner
                .unwrap_key(wrapped_key, master_key_identifier)
                .await
        })
    }
}

/// [`KmsClientFactory`] implementation that bridges to an asynchronous
/// [`AsyncKmsClientFactory`] using a [`ReenterAsync`] implementation
pub(crate) struct BridgeKmsClientFactory<R: ReenterAsync> {
    reenter: R,
    inner: Arc<dyn AsyncKmsClientFactory>,
}

impl<R: ReenterAsync> BridgeKmsClientFactory<R> {
    /// Create a new [`BridgeKmsClientFactory`] using the provided [`ReenterAsync`] implementation
    /// and asynchronous KMS client factory.
    pub(crate) fn new(
        reenter: R,
        inner: Arc<dyn AsyncKmsClientFactory>,
    ) -> BridgeKmsClientFactory<R> {
        BridgeKmsClientFactory { reenter, inner }
    }
}

impl<R: ReenterAsync> KmsClientFactory for BridgeKmsClientFactory<R> {
    fn create_client(
        &self,
        kms_connection_config: &crate::kms::KmsConnectionConfig,
    ) -> Result<KmsClientRef> {
        self.reenter.reenter(async move {
            let client = self.inner.create_client(kms_connection_config).await?;
            Ok(Arc::new(BridgeKmsClient::new(self.reenter.clone(), client)) as KmsClientRef)
        })
    }
}
