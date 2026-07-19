//! In-memory object body cache (moka, byte-weighted).
//!
//! Hybrid strategy (see architecture plan):
//! - Objects ≤ `object_max_bytes` are eligible for cache after a successful disk write
//! - Larger objects are streamed from disk and never cached
//! - Policy `None` makes every method a no-op

use std::sync::Arc;

use bytes::Bytes;
use flash_s3_common::{CacheConfig, CachePolicyKind};
use moka::future::Cache;

use crate::metrics::Metrics;

/// Process-local object cache keyed by `"{bucket}\0{key}"`.
#[derive(Clone)]
pub struct ObjectCache {
    inner: Option<Cache<String, Bytes>>,
    object_max_bytes: u64,
    metrics: Metrics,
}

impl ObjectCache {
    /// Build a cache from engine [`CacheConfig`].
    pub fn new(config: CacheConfig, metrics: Metrics) -> Self {
        let inner = match config.policy {
            CachePolicyKind::None => None,
            CachePolicyKind::InMemoryLru => {
                let cache = Cache::builder()
                    .weigher(|_k: &String, v: &Bytes| v.len().min(u32::MAX as usize) as u32)
                    .max_capacity(config.max_size_in_bytes)
                    .build();
                Some(cache)
            }
        };
        Self {
            inner,
            object_max_bytes: config.object_max_size_in_bytes,
            metrics,
        }
    }

    fn cache_key(bucket: &str, key: &str) -> String {
        format!("{bucket}\0{key}")
    }

    /// Lookup a cached body; updates hit/miss metrics.
    pub async fn get(&self, bucket: &str, key: &str) -> Option<Bytes> {
        let Some(cache) = &self.inner else {
            return None;
        };
        match cache.get(&Self::cache_key(bucket, key)).await {
            Some(v) => {
                self.metrics.cache_hits.inc();
                Some(v)
            }
            None => {
                self.metrics.cache_misses.inc();
                None
            }
        }
    }

    /// Insert if the body is within the per-object size cap.
    pub async fn insert(&self, bucket: &str, key: &str, data: Bytes) {
        let Some(cache) = &self.inner else {
            return;
        };
        if data.len() as u64 > self.object_max_bytes {
            return;
        }
        cache.insert(Self::cache_key(bucket, key), data).await;
        self.refresh_gauges(cache);
    }

    /// Drop a key after overwrite/delete.
    pub async fn invalidate(&self, bucket: &str, key: &str) {
        if let Some(cache) = &self.inner {
            cache.invalidate(&Self::cache_key(bucket, key)).await;
            self.refresh_gauges(cache);
        }
    }

    fn refresh_gauges(&self, cache: &Cache<String, Bytes>) {
        self.metrics.cache_entries.set(cache.entry_count() as i64);
        self.metrics.cache_bytes.set(cache.weighted_size() as i64);
    }

    /// Max object size eligible for caching.
    pub fn object_max_bytes(&self) -> u64 {
        self.object_max_bytes
    }

    /// Whether a cache backend is configured.
    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }
}

/// Shared cache handle stored in [`crate::AppState`].
pub type SharedObjectCache = Arc<ObjectCache>;
