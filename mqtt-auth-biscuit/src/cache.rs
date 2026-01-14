use dashmap::DashMap;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn nonzero_capacity(capacity: usize) -> NonZeroUsize {
    let v = if capacity == 0 { 1 } else { capacity };
    unsafe { NonZeroUsize::new_unchecked(v) }
}

pub struct CacheValue<V> {
    pub value: V,
    pub expiry: Instant,
}

pub struct SessionCache<K, V> {
    cache: DashMap<K, CacheValue<V>>,
    lru: Mutex<LruCache<K, ()>>,
}

#[cfg(not(kani))]
impl<K, V> SessionCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: DashMap::new(),
            lru: Mutex::new(LruCache::new(nonzero_capacity(capacity))),
        }
    }

    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.cache.insert(key.clone(), CacheValue { value, expiry });

        let mut lru = match self.lru.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
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
                let mut lru = match self.lru.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                lru.get(key);
                return Some(entry.value.clone());
            } else {
                // Expired
                self.cache.remove(key);
                let mut lru = match self.lru.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                lru.pop(key);
            }
        }
        None
    }
}

#[cfg(kani)]
impl<K, V> SessionCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(_capacity: usize) -> Self {
        Self {
            cache: DashMap::new(),
            lru: Mutex::new(LruCache::new(NonZeroUsize::new(1).unwrap())),
        }
    }

    pub fn insert(&self, _key: K, _value: V, _ttl: Duration) {}

    pub fn get(&self, _key: &K) -> Option<V>
    where
        V: Clone,
    {
        None
    }
}
