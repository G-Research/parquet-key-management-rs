use std::future::Future;

/// Trait for re-entering an async context from a sync context
pub trait ReenterAsync: Clone + Send + Sync + 'static {
    fn reenter<F: Future>(&self, f: F) -> F::Output;
}

/// [`ReenterAsync`] implementation for [`async-std`](async_std) runtime
#[cfg(feature = "async-std")]
#[derive(Clone)]
pub(crate) struct AsyncStdReenterAsync;

#[cfg(feature = "async-std")]
impl ReenterAsync for AsyncStdReenterAsync {
    fn reenter<F: Future>(&self, f: F) -> F::Output {
        async_std::task::block_on(f)
    }
}

/// [`ReenterAsync`] implementation for [`smol`] runtime
#[cfg(feature = "smol")]
#[derive(Clone)]
pub(crate) struct SmolReenterAsync;

#[cfg(feature = "smol")]
impl ReenterAsync for SmolReenterAsync {
    fn reenter<F: Future>(&self, f: F) -> F::Output {
        smol::block_on(f)
    }
}

/// [`ReenterAsync`] implementation for [`tokio`] runtime
/// This implementation will panic if called outside of a Tokio runtime context or if the runtime
/// is not multi-threaded.
#[cfg(feature = "tokio")]
#[derive(Clone)]
pub(crate) struct TokioReenterAsync;

#[cfg(feature = "tokio")]
impl ReenterAsync for TokioReenterAsync {
    fn reenter<F: Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    }
}
