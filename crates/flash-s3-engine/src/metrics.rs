use std::sync::Arc;

use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder, HistogramOpts,
    HistogramVec,
};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    pub cache_hits: IntCounter,
    pub cache_misses: IntCounter,
    pub cache_bytes: IntGauge,
    pub cache_entries: IntGauge,
    pub disk_read_bytes: IntCounter,
    pub disk_write_bytes: IntCounter,
    pub disk_op_duration: HistogramVec,
    pub s3_requests: IntCounterVec,
    pub multipart_inflight: IntGauge,
    pub panics: IntCounter,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let cache_hits = IntCounter::with_opts(Opts::new(
            "flashs3_cache_hits_total",
            "Number of object cache hits",
        ))?;
        let cache_misses = IntCounter::with_opts(Opts::new(
            "flashs3_cache_misses_total",
            "Number of object cache misses",
        ))?;
        let cache_bytes =
            IntGauge::with_opts(Opts::new("flashs3_cache_bytes", "Approximate cached bytes"))?;
        let cache_entries =
            IntGauge::with_opts(Opts::new("flashs3_cache_entries", "Number of cached objects"))?;
        let disk_read_bytes = IntCounter::with_opts(Opts::new(
            "flashs3_disk_read_bytes_total",
            "Bytes read from disk",
        ))?;
        let disk_write_bytes = IntCounter::with_opts(Opts::new(
            "flashs3_disk_write_bytes_total",
            "Bytes written to disk",
        ))?;
        let disk_op_duration = HistogramVec::new(
            HistogramOpts::new(
                "flashs3_disk_op_duration_seconds",
                "Disk operation latency",
            ),
            &["op"],
        )?;
        let s3_requests = IntCounterVec::new(
            Opts::new("flashs3_s3_requests_total", "S3 API requests"),
            &["method", "status", "op"],
        )?;
        let multipart_inflight = IntGauge::with_opts(Opts::new(
            "flashs3_multipart_uploads_inflight",
            "In-flight multipart uploads",
        ))?;
        let panics = IntCounter::with_opts(Opts::new(
            "flashs3_panics_total",
            "Caught panics in request handlers",
        ))?;

        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        registry.register(Box::new(cache_bytes.clone()))?;
        registry.register(Box::new(cache_entries.clone()))?;
        registry.register(Box::new(disk_read_bytes.clone()))?;
        registry.register(Box::new(disk_write_bytes.clone()))?;
        registry.register(Box::new(disk_op_duration.clone()))?;
        registry.register(Box::new(s3_requests.clone()))?;
        registry.register(Box::new(multipart_inflight.clone()))?;
        registry.register(Box::new(panics.clone()))?;

        Ok(Self {
            registry: Arc::new(registry),
            cache_hits,
            cache_misses,
            cache_bytes,
            cache_entries,
            disk_read_bytes,
            disk_write_bytes,
            disk_op_duration,
            s3_requests,
            multipart_inflight,
            panics,
        })
    }

    pub fn gather(&self) -> anyhow::Result<String> {
        let families = self.registry.gather();
        let mut buffer = Vec::new();
        TextEncoder::new().encode(&families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}
