//! Path helpers for the on-disk object layout.
//!
//! # Sharding
//!
//! `sha256(key)` → hex → `objects/{h[0:2]}/{h[2:4]}/{h}/current/`.
//! This keeps directory fan-out bounded (~65k leaf parents) without relying on
//! the logical key string (which may contain awkward path characters).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Hex-encoded SHA-256 of the UTF-8 object key (64 chars).
pub fn object_hash_hex(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(digest)
}

/// Directory that owns one logical object (`…/<hash>/`).
pub fn object_dir(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    let h = object_hash_hex(key);
    data_dir
        .join("buckets")
        .join(bucket)
        .join("objects")
        .join(&h[0..2])
        .join(&h[2..4])
        .join(&h)
}

/// Active version directory (`…/current/`). Versioning can later add `versions/`.
pub fn current_dir(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    object_dir(data_dir, bucket, key).join("current")
}

/// Object body path.
pub fn data_path(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    current_dir(data_dir, bucket, key).join("data")
}

/// Object metadata JSON path (content-type, etag, ACL, …).
pub fn meta_path(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    current_dir(data_dir, bucket, key).join("meta.json")
}

/// Bucket root directory.
pub fn bucket_dir(data_dir: &Path, bucket: &str) -> PathBuf {
    data_dir.join("buckets").join(bucket)
}

/// Bucket metadata file (`bucket.json`).
pub fn bucket_json_path(data_dir: &Path, bucket: &str) -> PathBuf {
    bucket_dir(data_dir, bucket).join("bucket.json")
}

/// Optional bucket policy JSON file.
pub fn bucket_policy_path(data_dir: &Path, bucket: &str) -> PathBuf {
    bucket_dir(data_dir, bucket).join("policy.json")
}

/// Optional bucket CORS configuration XML file.
pub fn bucket_cors_path(data_dir: &Path, bucket: &str) -> PathBuf {
    bucket_dir(data_dir, bucket).join("cors.xml")
}

/// Optional bucket tagging JSON file.
pub fn bucket_tags_path(data_dir: &Path, bucket: &str) -> PathBuf {
    bucket_dir(data_dir, bucket).join("tags.json")
}

/// Optional object tagging JSON file (alongside meta/data).
pub fn object_tags_path(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    current_dir(data_dir, bucket, key).join("tags.json")
}

/// Multipart staging directory for one upload id.
pub fn multipart_dir(data_dir: &Path, bucket: &str, upload_id: &str) -> PathBuf {
    bucket_dir(data_dir, bucket)
        .join("multipart")
        .join(upload_id)
}

/// Local multi-key credential store path.
pub fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("credentials.json")
}

/// redb key-index database path.
pub fn index_path(data_dir: &Path) -> PathBuf {
    data_dir.join("index").join("objects.redb")
}
