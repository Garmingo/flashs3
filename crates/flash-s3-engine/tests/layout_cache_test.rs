//! Layout hashing and in-process cache behavior.

use bytes::Bytes;
use flash_s3_common::{CacheConfig, CachePolicyKind, ObjectKey};
use flash_s3_engine::cache::ObjectCache;
use flash_s3_engine::metrics::Metrics;
use flash_s3_engine::storage::layout;

#[test]
fn object_hash_is_stable_and_sharded() {
    let h = layout::object_hash_hex("user/photo.jpg");
    assert_eq!(h.len(), 64);
    assert_eq!(layout::object_hash_hex("user/photo.jpg"), h);
    assert_ne!(layout::object_hash_hex("other"), h);

    let dir = layout::object_dir(std::path::Path::new("/data"), "b", "user/photo.jpg");
    let s = dir.to_string_lossy();
    assert!(s.contains(&format!("/objects/{}/{}/{}", &h[0..2], &h[2..4], h)));
    assert!(layout::current_dir(std::path::Path::new("/data"), "b", "k")
        .ends_with("current"));
}

#[tokio::test]
async fn cache_respects_object_max_and_policy_none() {
    let metrics = Metrics::new().unwrap();
    let cache = ObjectCache::new(
        CacheConfig {
            policy: CachePolicyKind::InMemoryLru,
            max_size_in_bytes: 1024 * 1024,
            object_max_size_in_bytes: 100,
        },
        metrics.clone(),
    );

    let small = Bytes::from(vec![1u8; 50]);
    let large = Bytes::from(vec![2u8; 200]);
    cache.insert("b", "small", small.clone()).await;
    cache.insert("b", "large", large).await;

    assert_eq!(cache.get("b", "small").await, Some(small));
    assert!(cache.get("b", "large").await.is_none());

    let none = ObjectCache::new(
        CacheConfig {
            policy: CachePolicyKind::None,
            max_size_in_bytes: 1024,
            object_max_size_in_bytes: 1024,
        },
        metrics,
    );
    none.insert("b", "x", Bytes::from_static(b"y")).await;
    assert!(none.get("b", "x").await.is_none());
    assert!(!none.enabled());
}

#[test]
fn object_key_used_in_hash_not_path() {
    // Keys with slashes must not create nested logical dirs in the hash layout —
    // only the sha256 path segments matter.
    let k = ObjectKey::new("a/b/c").unwrap();
    let h = layout::object_hash_hex(k.as_str());
    let p = layout::data_path(std::path::Path::new("/d"), "bucket", k.as_str());
    assert!(!p.to_string_lossy().contains("/a/b/c/"));
    assert!(p.to_string_lossy().contains(&h));
}
