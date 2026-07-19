use std::sync::Arc;

use bytes::Bytes;
use flash_s3_common::{CacheConfig, CachePolicyKind};
use moka::future::Cache;

use crate::metrics::Metrics;

#[derive(Clone)]
pub struct ObjectCache {
    inner: Option<Cache<String, Bytes>>,
    object_max_bytes: u64,
    metrics: Metrics,
}

impl ObjectCache {
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

    pub fn object_max_bytes(&self) -> u64 {
        self.object_max_bytes
    }

    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }
}

pub type SharedObjectCache = Arc<ObjectCache>;
