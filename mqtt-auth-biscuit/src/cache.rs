use dashmap::DashMap;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct CacheValue<V> {
    pub value: V,
    pub expiry: Instant,
}

pub struct SessionCache<K, V> {
    cache: DashMap<K, CacheValue<V>>,
    lru: Mutex<LruCache<K, ()>>,
}

impl<K, V> SessionCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: DashMap::new(),
            lru: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
        }
    }

    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.cache.insert(key.clone(), CacheValue { value, expiry });

        let mut lru = self.lru.lock().unwrap();
        if lru.put(key, ()).is_some() {
            // Already in LRU, just updated
        }
    }

    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        if let Some(entry) = self.cache.get(key) {
            if entry.expiry > Instant::now() {
                let mut lru = self.lru.lock().unwrap();
                lru.get(key);
                return Some(entry.value.clone());
            } else {
                // Expired
                self.cache.remove(key);
                let mut lru = self.lru.lock().unwrap();
                lru.pop(key);
            }
        }
        None
    }
}
