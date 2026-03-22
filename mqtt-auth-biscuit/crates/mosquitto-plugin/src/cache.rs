use dashmap::DashMap;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const fn nonzero_capacity(capacity: usize) -> NonZeroUsize {
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

    #[allow(clippy::needless_pass_by_value)]
    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        self.cache.insert(key.clone(), CacheValue { value, expiry });

        let mut lru = match self.lru.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let existed = lru.contains(&key);
        if let Some((evicted_key, ())) = lru.push(key.clone(), ()) {
            // LruCache::push returns the replaced entry for same-key updates.
            // Do not remove the freshly updated cache value in that case.
            if !(existed && evicted_key == key) {
                self.cache.remove(&evicted_key);
            }
        }
        while lru.len() > self.capacity {
            if let Some((evicted_key, ())) = lru.pop_lru() {
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
            }
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            drop(entry);
            // Expired
            self.cache.remove(key);
            let mut lru = match self.lru.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            lru.pop(key);
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    pub fn contains_live(&self, key: &K) -> bool {
        if let Some(entry) = self.cache.get(key) {
            if entry.expiry > Instant::now() {
                let mut lru = match self.lru.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                lru.get(key);
                return true;
            }
            drop(entry);
            self.cache.remove(key);
            let mut lru = match self.lru.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            lru.pop(key);
        }
        false
    }

    pub fn remove(&self, key: &K) -> bool {
        let removed = self.cache.remove(key).is_some();
        let mut lru = match self.lru.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        lru.pop(key);
        removed
    }

    /// Returns a snapshot of cache hit/miss counts for observability.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.metrics.hits.load(Ordering::Relaxed),
            misses: self.metrics.misses.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionCache;
    use std::thread;
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

    #[test]
    fn remove_deletes_existing_key() {
        let cache = SessionCache::new(2);
        cache.insert("a".to_string(), 1, Duration::from_secs(60));

        assert!(cache.remove(&"a".to_string()));
        assert_eq!(cache.get(&"a".to_string()), None);
    }

    #[test]
    fn remove_returns_false_for_missing_key() {
        let cache: SessionCache<String, i32> = SessionCache::new(2);
        assert!(!cache.remove(&"missing".to_string()));
    }

    #[test]
    fn contains_live_returns_true_for_unexpired_entry() {
        let cache = SessionCache::new(2);
        cache.insert("a".to_string(), 1, Duration::from_secs(60));

        assert!(cache.contains_live(&"a".to_string()));
    }

    #[test]
    fn contains_live_purges_expired_entry() {
        let cache = SessionCache::new(2);
        cache.insert("a".to_string(), 1, Duration::from_millis(1));
        thread::sleep(Duration::from_millis(10));

        assert!(!cache.contains_live(&"a".to_string()));
        assert_eq!(cache.get(&"a".to_string()), None);
    }

    #[test]
    fn reinsert_same_key_keeps_entry_live() {
        let cache = SessionCache::new(2);
        cache.insert("a".to_string(), 1, Duration::from_secs(60));
        cache.insert("a".to_string(), 2, Duration::from_secs(60));

        assert_eq!(cache.get(&"a".to_string()), Some(2));
    }

    #[test]
    fn reinsert_same_key_preserves_lru_eviction_semantics() {
        let cache = SessionCache::new(2);
        cache.insert("a".to_string(), 1, Duration::from_secs(60));
        cache.insert("b".to_string(), 2, Duration::from_secs(60));
        cache.insert("a".to_string(), 3, Duration::from_secs(60));
        cache.insert("c".to_string(), 4, Duration::from_secs(60));

        assert_eq!(cache.get(&"a".to_string()), Some(3));
        assert_eq!(cache.get(&"b".to_string()), None);
        assert_eq!(cache.get(&"c".to_string()), Some(4));
    }

    #[test]
    fn reinsert_same_key_refreshes_ttl() {
        let cache = SessionCache::new(2);
        cache.insert("a".to_string(), 1, Duration::from_millis(20));
        thread::sleep(Duration::from_millis(10));
        cache.insert("a".to_string(), 2, Duration::from_millis(80));
        thread::sleep(Duration::from_millis(40));

        assert_eq!(cache.get(&"a".to_string()), Some(2));
    }
}
