use crate::errors::Result;
use crate::kms::{KmsClientFactory, KmsClientRef, KmsConnectionConfig, KmsConnectionInfo};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError, TryLockError};
use std::time::{Duration, Instant};

/// Cache of key encryption keys (KEKs) to use when decrypting files,
/// keyed by their base64 encoded key id
pub(crate) type KekReadCache = Arc<ExpiringCache<String, Vec<u8>>>;

// Key encryption key (KEK) struct with extra metadata required when encrypting files
pub(crate) struct KeyEncryptionKey {
    pub key_id: Vec<u8>,
    pub encoded_key_id: String,
    pub key: Vec<u8>,
    pub wrapped_key: String,
}

/// Cache of key encryption keys (KEKs) used when encrypting files,
/// keyed by the corresponding master key identifier.
pub(crate) type KekWriteCache = Arc<ExpiringCache<String, Arc<KeyEncryptionKey>>>;

/// Manages caching KMS clients and KEK caches
pub(crate) struct KmsManager {
    kms_client_factory: Box<dyn KmsClientFactory>,
    kms_client_cache: ExpiringCache<KmsInstanceKey, KmsClientRef>,
    kek_read_caches: ExpiringCache<KekCacheKey, KekReadCache>,
    kek_write_caches: ExpiringCache<KmsInstanceKey, KekWriteCache>,
}

impl KmsManager {
    pub fn new<T>(kms_client_factory: T) -> Self
    where
        T: KmsClientFactory + 'static,
    {
        Self {
            kms_client_factory: Box::new(kms_client_factory),
            kms_client_cache: ExpiringCache::new(),
            kek_read_caches: ExpiringCache::new(),
            kek_write_caches: ExpiringCache::new(),
        }
    }

    pub fn get_client(
        &self,
        kms_connection_config: &Arc<KmsConnectionConfig>,
        cache_lifetime: Option<Duration>,
    ) -> Result<KmsClientRef> {
        self.clear_expired_entries(cache_lifetime);
        // Take a snapshot of the connection config so that the cache key and created client
        // use the same access token, even if the token is refreshed concurrently.
        let kms_connection_info = kms_connection_config.connection_info();
        let key = KmsInstanceKey::new(&kms_connection_info);
        self.kms_client_cache
            .get_or_create(key, cache_lifetime, || {
                self.kms_client_factory.create_client(&kms_connection_info)
            })
    }

    pub fn get_kek_read_cache(
        &self,
        kms_connection_config: &Arc<KmsConnectionConfig>,
        cache_lifetime: Option<Duration>,
    ) -> KekReadCache {
        self.clear_expired_entries(cache_lifetime);
        let key = KekCacheKey::new(kms_connection_config.key_access_token().clone());
        self.kek_read_caches
            .get_or_create(key, cache_lifetime, || Ok(Arc::new(ExpiringCache::new())))
            .unwrap()
    }

    pub fn get_kek_write_cache(
        &self,
        kms_connection_config: &Arc<KmsConnectionConfig>,
        cache_lifetime: Option<Duration>,
    ) -> KekWriteCache {
        self.clear_expired_entries(cache_lifetime);
        // KEKs are wrapped by a specific KMS instance, so they can't be shared between instances
        let key = KmsInstanceKey::new(&kms_connection_config.connection_info());
        self.kek_write_caches
            .get_or_create(key, cache_lifetime, || Ok(Arc::new(ExpiringCache::new())))
            .unwrap()
    }

    fn clear_expired_entries(&self, cleanup_interval: Option<Duration>) {
        if let Some(cleanup_interval) = cleanup_interval {
            self.kms_client_cache.clear_expired(cleanup_interval);
            self.kek_read_caches.clear_expired(cleanup_interval);
            self.kek_write_caches.clear_expired(cleanup_interval);
        }
    }

    #[cfg(test)]
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            num_kms_clients: self.kms_client_cache.len(),
            num_kek_read_caches: self.kek_read_caches.len(),
            num_kek_write_caches: self.kek_write_caches.len(),
        }
    }
}

/// A cache of values that are created on demand and may expire.
///
/// Each key has its own slot with a separate lock, so that creating a value for one key,
/// which may involve calling user code and making network requests, doesn't block access
/// to other keys. Concurrent requests for the same missing key wait for the first request
/// to create the value rather than duplicating the work.
pub(crate) struct ExpiringCache<TKey, TValue> {
    slots: Mutex<HashMap<TKey, Arc<CacheSlot<TValue>>>>,
    last_cleanup: Mutex<Instant>,
}

type CacheSlot<TValue> = Mutex<SlotState<TValue>>;

struct SlotState<TValue> {
    value: Option<ExpiringCacheValue<TValue>>,
    /// Set when the slot has been removed from the cache, so that any request still holding
    /// a reference to the slot knows to retry with a new slot rather than using this one.
    removed: bool,
}

impl<TValue> Default for SlotState<TValue> {
    fn default() -> Self {
        Self {
            value: None,
            removed: false,
        }
    }
}

impl<TValue> SlotState<TValue> {
    fn has_valid_value(&self) -> bool {
        self.value.as_ref().is_some_and(|value| value.is_valid())
    }
}

#[derive(Debug)]
struct ExpiringCacheValue<TValue> {
    value: TValue,
    expiration_time: Option<Instant>,
}

impl<TValue> ExpiringCacheValue<TValue> {
    pub fn new(value: TValue, cache_duration: Option<Duration>) -> Self {
        Self {
            value,
            expiration_time: cache_duration.map(|d| now() + d),
        }
    }

    pub fn is_valid(&self) -> bool {
        match self.expiration_time {
            None => true,
            Some(expiration_time) => now() < expiration_time,
        }
    }
}

impl<TKey, TValue> ExpiringCache<TKey, TValue>
where
    TKey: Clone + Eq + Hash,
    TValue: Clone,
{
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::default()),
            last_cleanup: Mutex::new(now()),
        }
    }

    /// Get the cached value for a key, or create it if there is no valid cached value.
    /// The creator function is called without holding the lock on the whole cache,
    /// so it only blocks other requests for the same key.
    /// If the creator fails, the key's slot is removed so that failed keys don't accumulate.
    pub fn get_or_create<F>(
        &self,
        key: TKey,
        cache_lifetime: Option<Duration>,
        creator: F,
    ) -> Result<TValue>
    where
        F: FnOnce() -> Result<TValue>,
    {
        loop {
            let slot = self
                .slots
                .lock()
                .unwrap()
                .entry(key.clone())
                .or_default()
                .clone();
            // The lock is only poisoned if a creator function panicked, which leaves either no value
            // or a previously cached value in the slot, so it's safe to ignore the poisoning.
            let mut state = slot.lock().unwrap_or_else(PoisonError::into_inner);
            if state.removed {
                // The slot was removed from the cache after we got it from the map,
                // either because it expired or because creating its value failed.
                continue;
            }
            if let Some(value) = &state.value {
                if value.is_valid() {
                    return Ok(value.value.clone());
                }
            }
            return match creator() {
                Ok(value) => {
                    state.value = Some(ExpiringCacheValue::new(value.clone(), cache_lifetime));
                    Ok(value)
                }
                Err(e) => {
                    self.remove_slot(&key, &slot, &mut state);
                    Err(e)
                }
            };
        }
    }

    /// Remove a slot from the cache. The slot's lock must be held by the caller.
    fn remove_slot(
        &self,
        key: &TKey,
        slot: &Arc<CacheSlot<TValue>>,
        state: &mut SlotState<TValue>,
    ) {
        state.removed = true;
        let mut slots = self.slots.lock().unwrap();
        if slots
            .get(key)
            .is_some_and(|map_slot| Arc::ptr_eq(map_slot, slot))
        {
            slots.remove(key);
        }
    }

    /// Remove any expired entries from the cache
    pub fn clear_expired(&self, cleanup_interval: Duration) {
        {
            let mut last_cleanup = self.last_cleanup.lock().unwrap();
            let instant_now = now();
            if (instant_now - *last_cleanup) < cleanup_interval {
                return;
            }
            *last_cleanup = instant_now;
        }

        self.slots.lock().unwrap().retain(|_, slot| {
            let mut state = match slot.try_lock() {
                Ok(state) => state,
                Err(TryLockError::Poisoned(state)) => state.into_inner(),
                // A value is currently being created for this key
                Err(TryLockError::WouldBlock) => return true,
            };
            // Mark the slot as removed while holding its lock, so that a concurrent
            // request that already has a reference to it won't store a value in it.
            let keep = state.has_valid_value();
            state.removed = !keep;
            keep
        });
    }

    /// Get the number of entries in the cache, including expired values that haven't been
    /// removed and values that are currently being created
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.lock().unwrap().len()
    }
}

/// Key used to cache KMS clients and KEK write caches
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct KmsInstanceKey {
    key_access_token: String,
    kms_instance_id: String,
    kms_instance_url: String,
}

impl KmsInstanceKey {
    pub fn new(kms_connection_info: &KmsConnectionInfo) -> Self {
        Self {
            key_access_token: kms_connection_info.key_access_token().to_owned(),
            kms_instance_id: kms_connection_info.kms_instance_id().to_owned(),
            kms_instance_url: kms_connection_info.kms_instance_url().to_owned(),
        }
    }
}

// Key used to cache KEK read caches.
// KEK IDs are globally unique, so read caches can be shared between KMS instances.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct KekCacheKey {
    key_access_token: String,
}

impl KekCacheKey {
    pub fn new(key_access_token: String) -> Self {
        Self { key_access_token }
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct CacheStats {
    pub num_kms_clients: usize,
    pub num_kek_read_caches: usize,
    pub num_kek_write_caches: usize,
}

#[cfg(not(test))]
#[inline(always)]
fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
fn now() -> Instant {
    mock_time::now()
}

#[cfg(test)]
pub mod mock_time {
    //! Allows controlling the time returned by now() for testing cache behaviour
    use std::sync::{Mutex, MutexGuard, RwLock};
    use std::time::{Duration, Instant};

    static MOCK_NOW: RwLock<Option<Instant>> = RwLock::new(None);

    // Mutex to prevent multiple tests controlling time concurrently
    static CONTROL_MUTEX: Mutex<()> = Mutex::new(());

    pub struct TimeController {
        _control_guard: MutexGuard<'static, ()>,
    }

    impl TimeController {
        /// Advance the time returned by `now` by the specified duration
        pub fn advance(&self, duration: Duration) {
            let mut now_lock = MOCK_NOW.write().unwrap();
            if let Some(now) = &mut *now_lock {
                *now += duration;
            }
        }
    }

    impl Drop for TimeController {
        fn drop(&mut self) {
            // Revert to using the real time so that tests not holding a controller
            // don't observe mocked time left over from a previous test
            let mut now_lock = MOCK_NOW.write().unwrap();
            *now_lock = None;
        }
    }

    /// Get the current time
    pub fn now() -> Instant {
        let now_lock = MOCK_NOW.read().unwrap();
        now_lock.unwrap_or_else(Instant::now)
    }

    /// Get a [`TimeController`] that can be used to advance the time in a test
    pub fn time_controller() -> TimeController {
        let control_guard = CONTROL_MUTEX.lock().unwrap();
        {
            let mut now_guard = MOCK_NOW.write().unwrap();
            *now_guard = Some(Instant::now());
        }
        TimeController {
            _control_guard: control_guard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error;
    use crate::kms::KmsClient;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Barrier};
    use std::thread;

    struct NoOpKmsClient;

    impl KmsClient for NoOpKmsClient {
        fn wrap_key(&self, _key_bytes: &[u8], _master_key_identifier: &str) -> Result<String> {
            Err(Error::General("Not implemented".to_owned()))
        }

        fn unwrap_key(&self, _wrapped_key: &str, _master_key_identifier: &str) -> Result<Vec<u8>> {
            Err(Error::General("Not implemented".to_owned()))
        }
    }

    /// A KMS client factory that refreshes the access token from another thread
    /// while a client is being created.
    struct RefreshingKmsClientFactory {
        kms_connection_config: Arc<KmsConnectionConfig>,
    }

    impl KmsClientFactory for RefreshingKmsClientFactory {
        fn create_client(&self, kms_connection_info: &KmsConnectionInfo) -> Result<KmsClientRef> {
            let config = self.kms_connection_config.clone();
            thread::spawn(move || {
                config.refresh_key_access_token("refreshed_token".to_owned());
            })
            .join()
            .unwrap();
            // The client is created with the token that was used for the cache key
            assert_eq!(kms_connection_info.key_access_token(), "initial_token");
            assert_eq!(
                self.kms_connection_config.key_access_token(),
                "refreshed_token"
            );
            Ok(Arc::new(NoOpKmsClient))
        }
    }

    #[test]
    fn test_refresh_token_during_client_creation() {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let config = Arc::new(
                KmsConnectionConfig::builder()
                    .set_key_access_token("initial_token".to_owned())
                    .build(),
            );
            let kms_manager = KmsManager::new(RefreshingKmsClientFactory {
                kms_connection_config: config.clone(),
            });
            let result = kms_manager.get_client(&config, None).map(|_| ());
            sender.send(result).unwrap();
        });

        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(result) => result.unwrap(),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("Deadlock creating KMS client while refreshing the access token")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("Client creation thread panicked"),
        }
    }

    /// Run a function on another thread and panic if it doesn't complete within a timeout
    fn run_with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || sender.send(f()).unwrap());
        receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("Operation did not complete")
    }

    #[test]
    fn test_cache_creation_does_not_block_other_keys() {
        let cache = Arc::new(ExpiringCache::<&str, i32>::new());
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel::<()>();

        let slow_creation = {
            let cache = cache.clone();
            thread::spawn(move || {
                cache.get_or_create("a", None, || {
                    started_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    Ok(1)
                })
            })
        };
        started_receiver.recv().unwrap();

        // Other keys can be created and read while a value is being created for "a"
        let value = run_with_timeout({
            let cache = cache.clone();
            move || cache.get_or_create("b", None, || Ok(2)).unwrap()
        });
        assert_eq!(value, 2);
        let value = run_with_timeout({
            let cache = cache.clone();
            move || {
                cache
                    .get_or_create("b", None, || panic!("Should be cached"))
                    .unwrap()
            }
        });
        assert_eq!(value, 2);

        // Clearing expired entries doesn't wait for the value to be created
        run_with_timeout({
            let cache = cache.clone();
            move || cache.clear_expired(Duration::ZERO)
        });

        release_sender.send(()).unwrap();
        assert_eq!(slow_creation.join().unwrap().unwrap(), 1);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_concurrent_requests_create_value_once() {
        let cache = Arc::new(ExpiringCache::<&str, i32>::new());
        let creation_count = Arc::new(AtomicUsize::new(0));
        let num_threads = 8;
        let barrier = Arc::new(Barrier::new(num_threads));

        let threads: Vec<_> = (0..num_threads)
            .map(|_| {
                let cache = cache.clone();
                let creation_count = creation_count.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    cache.get_or_create("a", None, || {
                        creation_count.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(50));
                        Ok(1)
                    })
                })
            })
            .collect();

        for thread in threads {
            assert_eq!(thread.join().unwrap().unwrap(), 1);
        }
        assert_eq!(creation_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_cache_creation_panic_does_not_poison_cache() {
        let cache = Arc::new(ExpiringCache::<&str, i32>::new());

        let result = thread::spawn({
            let cache = cache.clone();
            move || cache.get_or_create("a", None, || panic!("Creation failed"))
        })
        .join();
        assert!(result.is_err());

        // The panic leaves an empty slot behind, which can be cleared or reused
        assert_eq!(cache.len(), 1);
        cache.clear_expired(Duration::ZERO);
        assert_eq!(cache.len(), 0);
        let result = thread::spawn({
            let cache = cache.clone();
            move || cache.get_or_create("a", None, || panic!("Creation failed"))
        })
        .join();
        assert!(result.is_err());

        assert_eq!(cache.get_or_create("a", None, || Ok(1)).unwrap(), 1);
        assert_eq!(cache.get_or_create("b", None, || Ok(2)).unwrap(), 2);
        cache.clear_expired(Duration::ZERO);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_creation_error_is_not_cached() {
        let cache = ExpiringCache::<&str, i32>::new();
        let result = cache.get_or_create("a", None, || Err(Error::General("Failed".to_owned())));
        assert!(result.is_err());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get_or_create("a", None, || Ok(1)).unwrap(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_waiting_request_retries_after_creation_error() {
        let cache = Arc::new(ExpiringCache::<&str, i32>::new());
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel::<()>();

        let failed_creation = {
            let cache = cache.clone();
            thread::spawn(move || {
                cache.get_or_create("a", None, || {
                    started_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    Err(Error::General("Failed".to_owned()))
                })
            })
        };
        started_receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap();

        // Start a second request that waits on the slot for "a" while the first creation is in
        // progress. The failed creation removes the slot, so this request must create the value
        // in a new slot rather than in the removed one.
        let waiting_creation = {
            let cache = cache.clone();
            thread::spawn(move || cache.get_or_create("a", None, || Ok(2)))
        };
        thread::sleep(Duration::from_millis(100));
        release_sender.send(()).unwrap();

        assert!(failed_creation.join().unwrap().is_err());
        assert_eq!(waiting_creation.join().unwrap().unwrap(), 2);
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache
                .get_or_create("a", None, || panic!("Should be cached"))
                .unwrap(),
            2
        );
    }

    #[test]
    fn test_cache_cleared_slot_is_not_reused() {
        let time_controller = mock_time::time_controller();
        let cache = ExpiringCache::<&str, i32>::new();
        cache
            .get_or_create("a", Some(Duration::from_secs(10)), || Ok(1))
            .unwrap();

        // Simulate a request that got the slot from the map before it was cleared
        let slot = cache.slots.lock().unwrap().get("a").unwrap().clone();
        time_controller.advance(Duration::from_secs(20));
        cache.clear_expired(Duration::from_secs(10));
        assert_eq!(cache.len(), 0);
        assert!(slot.lock().unwrap().removed);
    }
}
