//! In-process micro-benchmarks (no HTTP/SigV4 overhead).
//!
//! Measures raw store write, disk read, and moka cache hit latency/throughput.
//!
//! ```bash
//! cargo run -p flash-s3-engine --example micro_bench --release
//! ```

use std::time::Instant;

use bytes::Bytes;
use flash_s3_common::{CacheConfig, CachePolicyKind, CannedAcl, CanonicalUserId, ObjectKey};
use flash_s3_engine::cache::ObjectCache;
use flash_s3_engine::metrics::Metrics;
use flash_s3_engine::storage::{ObjectStore, PutObjectOpts};

fn opts(owner: &CanonicalUserId) -> PutObjectOpts {
    PutObjectOpts {
        content_type: Some("application/octet-stream".into()),
        canned_acl: Some(CannedAcl::Private),
        acl: None,
        owner: owner.clone(),
        owner_display_name: "bench".into(),
        default_object_acl: CannedAcl::Private,
        user_meta: Default::default(),
        content_encoding: None,
        cache_control: None,
        content_disposition: None,
        content_language: None,
        expires: None,
        checksums: Default::default(),
        sse_s3: false,
        sse_nonce: None,
        plaintext_size: None,
        etag_override: None,
    }
}

fn report(name: &str, ops: usize, bytes: u64, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64().max(1e-9);
    println!(
        "  {name:22}  {ops:6} ops  {:>8.1} ops/s  {:>8.2} MiB/s  ({elapsed:?})",
        ops as f64 / secs,
        (bytes as f64 / (1024.0 * 1024.0)) / secs
    );
}

#[tokio::main]
async fn main() {
    let objects: usize = std::env::var("BENCH_OBJECTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let size: usize = std::env::var("BENCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64 * 1024);

    println!("FlashS3 micro_bench (in-process)");
    println!("  objects={objects}  size={size} B");

    let tmp = tempfile::tempdir().expect("tempdir");
    let metrics = Metrics::new().expect("metrics");
    let store = ObjectStore::open(tmp.path().to_path_buf(), metrics.clone()).expect("store");
    let cache = ObjectCache::new(
        CacheConfig {
            policy: CachePolicyKind::InMemoryLru,
            max_size_in_bytes: 512 * 1024 * 1024,
            object_max_size_in_bytes: 8 * 1024 * 1024,
        },
        metrics,
    );
    let owner = CanonicalUserId::new("bench");
    store
        .create_bucket("bench", owner.clone(), "bench", CannedAcl::Private)
        .await
        .unwrap();

    let payload = Bytes::from(vec![0xABu8; size]);
    let keys: Vec<ObjectKey> = (0..objects)
        .map(|i| ObjectKey::new(format!("k-{i:06}")).unwrap())
        .collect();

    // WRITE
    let t0 = Instant::now();
    for key in &keys {
        store
            .put_object("bench", key, payload.clone(), opts(&owner))
            .await
            .unwrap();
    }
    report("disk_write", objects, (objects * size) as u64, t0.elapsed());

    // DISK READ (no cache)
    let t0 = Instant::now();
    let mut nbytes = 0u64;
    for key in &keys {
        let (_, data) = store.read_object_bytes("bench", key).await.unwrap();
        nbytes += data.len() as u64;
    }
    report("disk_read", objects, nbytes, t0.elapsed());

    // FILL CACHE
    let t0 = Instant::now();
    for key in &keys {
        let (_, data) = store.read_object_bytes("bench", key).await.unwrap();
        cache.insert("bench", key.as_str(), data).await;
    }
    report("cache_fill", objects, (objects * size) as u64, t0.elapsed());

    // CACHE HIT READ
    let t0 = Instant::now();
    let mut nbytes = 0u64;
    for key in &keys {
        let data = cache.get("bench", key.as_str()).await.expect("cached");
        nbytes += data.len() as u64;
    }
    report("cache_hit_read", objects, nbytes, t0.elapsed());

    // Fresh latency sample for a fair disk vs cache comparison
    let sample = objects.min(100);
    let t0 = Instant::now();
    for key in keys.iter().take(sample) {
        let _ = store.read_object_bytes("bench", key).await.unwrap();
    }
    let disk_sample = t0.elapsed().as_secs_f64() / sample as f64;

    let t0 = Instant::now();
    for key in keys.iter().take(sample) {
        let _ = cache.get("bench", key.as_str()).await.unwrap();
    }
    let cache_sample = t0.elapsed().as_secs_f64() / sample as f64;

    println!(
        "  avg latency sample (n={sample}): disk_read={:.3}ms  cache_hit={:.3}ms  speedup={:.1}x",
        disk_sample * 1000.0,
        cache_sample * 1000.0,
        disk_sample / cache_sample.max(1e-12)
    );
}
