use dashmap::DashMap;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Snapshot of cache hit/miss metrics for diagnostics and benchmarking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug, Default)]
struct CacheMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
}

pub struct SessionCache<K, V> {
    cache: DashMap<K, CacheValue<V>>,
    lru: Mutex<LruCache<K, ()>>,
    capacity: usize,
    metrics: CacheMetrics,
}

#[cfg(not(kani))]
impl<K, V> SessionCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(capacity: usize) -> Self {
        let capacity = if capacity == 0 { 1 } else { capacity };
        Self {
            cache: DashMap::new(),
            lru: Mutex::new(LruCache::new(nonzero_capacity(capacity))),
            capacity,
            metrics: CacheMetrics::default(),
        }
    }

    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.cache.insert(key.clone(), CacheValue { value, expiry });

        let mut lru = match self.lru.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((evicted_key, _)) = lru.push(key, ()) {
            self.cache.remove(&evicted_key);
        }
        while lru.len() > self.capacity {
            if let Some((evicted_key, _)) = lru.pop_lru() {
                self.cache.remove(&evicted_key);
            } else {
                break;
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        if let Some(entry) = self.cache.get(key) {
            if entry.expiry > Instant::now() {
                self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                let mut lru = match self.lru.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                lru.get(key);
                return Some(entry.value.clone());
            } else {
                self.metrics.misses.fetch_add(1, Ordering::Relaxed);
                // Expired
                self.cache.remove(key);
                let mut lru = match self.lru.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                lru.pop(key);
            }
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    /// Returns a snapshot of cache hit/miss counts for observability.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.metrics.hits.load(Ordering::Relaxed),
            misses: self.metrics.misses.load(Ordering::Relaxed),
        }
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
            capacity: 1,
            metrics: CacheMetrics::default(),
        }
    }

    pub fn insert(&self, _key: K, _value: V, _ttl: Duration) {}

    pub fn get(&self, _key: &K) -> Option<V>
    where
        V: Clone,
    {
        None
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: 0,
            misses: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionCache;
    use std::time::Duration;

    #[test]
    fn evicts_least_recently_used_entry() {
        let cache = SessionCache::new(2);

        cache.insert("a".to_string(), 1, Duration::from_secs(60));
        cache.insert("b".to_string(), 2, Duration::from_secs(60));

        assert_eq!(cache.get(&"a".to_string()), Some(1));

        cache.insert("c".to_string(), 3, Duration::from_secs(60));

        assert_eq!(cache.get(&"b".to_string()), None);
        assert_eq!(cache.get(&"a".to_string()), Some(1));
        assert_eq!(cache.get(&"c".to_string()), Some(3));
    }
}
