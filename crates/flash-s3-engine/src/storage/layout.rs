use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// 4-hex (2+2) sharded path for an object key.
pub fn object_hash_hex(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(digest)
}

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

pub fn current_dir(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    object_dir(data_dir, bucket, key).join("current")
}

pub fn data_path(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    current_dir(data_dir, bucket, key).join("data")
}

pub fn meta_path(data_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    current_dir(data_dir, bucket, key).join("meta.json")
}

pub fn bucket_dir(data_dir: &Path, bucket: &str) -> PathBuf {
    data_dir.join("buckets").join(bucket)
}

pub fn bucket_json_path(data_dir: &Path, bucket: &str) -> PathBuf {
    bucket_dir(data_dir, bucket).join("bucket.json")
}

pub fn bucket_policy_path(data_dir: &Path, bucket: &str) -> PathBuf {
    bucket_dir(data_dir, bucket).join("policy.json")
}

pub fn multipart_dir(data_dir: &Path, bucket: &str, upload_id: &str) -> PathBuf {
    bucket_dir(data_dir, bucket)
        .join("multipart")
        .join(upload_id)
}

pub fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("credentials.json")
}

pub fn index_path(data_dir: &Path) -> PathBuf {
    data_dir.join("index").join("objects.redb")
}
