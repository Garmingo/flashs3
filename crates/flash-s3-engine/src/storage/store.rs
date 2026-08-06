//! Disk-backed object store: buckets, objects, multipart, ACLs, policies, CORS.
//!
//! All mutating object paths take a per-`(bucket,key)` async mutex and write
//! via temp file + `fsync` + `rename` for crash-safe puts.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::{SecondsFormat, Utc};
use dashmap::DashMap;
use flash_s3_common::{
    AccessControlPolicy, BucketPolicy, CannedAcl, CanonicalUserId, FlashError, ObjectKey,
    validate_bucket_name,
};
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::metrics::Metrics;
use crate::storage::index::{IndexEntry, ObjectIndex};
use crate::storage::layout;

/// Persisted bucket metadata (`bucket.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    /// Bucket name.
    pub name: String,
    /// Creation timestamp (RFC3339).
    pub created: String,
    /// Owning canonical user id.
    pub owner: CanonicalUserId,
    /// Owner display name.
    pub owner_display_name: String,
    /// Bucket ACL.
    pub acl: AccessControlPolicy,
    /// Default canned ACL for new objects without `x-amz-acl`.
    pub default_object_acl: CannedAcl,
}

/// Persisted object metadata (`meta.json` under `current/`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Object key.
    pub key: String,
    /// Body size in bytes.
    pub size: u64,
    /// Quoted ETag.
    pub etag: String,
    /// MIME type.
    pub content_type: String,
    /// Additional representation coding, excluding the aws-chunked transport coding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    /// Cache policy returned to object readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// Suggested download presentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    /// Natural language of the representation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_language: Option<String>,
    /// Expiration date supplied by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Last modification time (RFC3339).
    pub last_modified: String,
    /// Object owner.
    pub owner: CanonicalUserId,
    /// Owner display name.
    pub owner_display_name: String,
    /// Per-object ACL (rich grants).
    pub acl: AccessControlPolicy,
    /// `x-amz-meta-*` user metadata.
    #[serde(default)]
    pub user_meta: std::collections::HashMap<String, String>,
    /// Validated object checksums, keyed by the S3 response header name.
    #[serde(default)]
    pub checksums: std::collections::HashMap<String, String>,
}

/// Options for [`ObjectStore::put_object`] / copy / stream puts.
#[derive(Debug, Clone)]
pub struct PutObjectOpts {
    /// Optional Content-Type (defaults to `application/octet-stream`).
    pub content_type: Option<String>,
    /// Optional canned ACL from `x-amz-acl`.
    pub canned_acl: Option<CannedAcl>,
    /// Fully resolved ACL (wins over canned when set).
    pub acl: Option<AccessControlPolicy>,
    /// Uploading principal.
    pub owner: CanonicalUserId,
    /// Display name for owner.
    pub owner_display_name: String,
    /// Bucket default when neither canned nor full ACL is set.
    pub default_object_acl: CannedAcl,
    /// User metadata map.
    pub user_meta: std::collections::HashMap<String, String>,
    /// Standard object response metadata.
    pub content_encoding: Option<String>,
    pub cache_control: Option<String>,
    pub content_disposition: Option<String>,
    pub content_language: Option<String>,
    pub expires: Option<String>,
    /// Validated request checksum values.
    pub checksums: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultipartMeta {
    pub upload_id: String,
    pub key: String,
    pub initiated: String,
    pub owner: CanonicalUserId,
    pub owner_display_name: String,
    pub content_type: Option<String>,
    pub canned_acl: Option<CannedAcl>,
    pub parts: Vec<MultipartPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultipartPart {
    pub part_number: i32,
    pub etag: String,
    pub size: u64,
}

/// Local filesystem store + listing index.
///
/// Cheap to clone (`Arc` internals); share one instance via [`crate::AppState`].
#[derive(Clone)]
pub struct ObjectStore {
    data_dir: PathBuf,
    index: ObjectIndex,
    locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    multipart_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    multipart_part_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    metrics: Metrics,
}

impl ObjectStore {
    /// Open (or create) the data directory and listing index.
    pub fn open(data_dir: PathBuf, metrics: Metrics) -> Result<Self, FlashError> {
        std::fs::create_dir_all(&data_dir).map_err(io_err)?;
        std::fs::create_dir_all(data_dir.join("buckets")).map_err(io_err)?;
        std::fs::create_dir_all(data_dir.join("index")).map_err(io_err)?;
        let index = ObjectIndex::open(&layout::index_path(&data_dir))?;
        Ok(Self {
            data_dir,
            index,
            locks: Arc::new(DashMap::new()),
            multipart_locks: Arc::new(DashMap::new()),
            multipart_part_locks: Arc::new(DashMap::new()),
            metrics,
        })
    }

    /// Configured data root.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Readiness probe: data dir exists and is writable.
    pub fn is_ready(&self) -> bool {
        self.data_dir.exists()
            && std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.data_dir.join(".write_test"))
                .map(|_| {
                    let _ = std::fs::remove_file(self.data_dir.join(".write_test"));
                    true
                })
                .unwrap_or(false)
    }

    fn lock_for(&self, bucket: &str, key: &str) -> Arc<Mutex<()>> {
        let k = format!("{bucket}/{key}");
        self.locks
            .entry(k)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Serialize mutations to one multipart upload's manifest.
    fn multipart_lock_for(&self, bucket: &str, upload_id: &str) -> Arc<Mutex<()>> {
        let k = format!("{bucket}/{upload_id}");
        self.multipart_locks
            .entry(k)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Serialize replacement writes to one part number while allowing different
    /// parts of the same upload to stream concurrently.
    fn multipart_part_lock_for(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: i32,
    ) -> Arc<Mutex<()>> {
        let k = format!("{bucket}/{upload_id}/{part_number}");
        self.multipart_part_locks
            .entry(k)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Create an empty bucket with a private bucket ACL.
    pub async fn create_bucket(
        &self,
        name: &str,
        owner: CanonicalUserId,
        display_name: &str,
        default_object_acl: CannedAcl,
    ) -> Result<BucketInfo, FlashError> {
        validate_bucket_name(name)?;
        let path = layout::bucket_json_path(&self.data_dir, name);
        if path.exists() {
            return Err(FlashError::BucketAlreadyOwnedByYou);
        }
        let info = BucketInfo {
            name: name.to_string(),
            created: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: owner.clone(),
            owner_display_name: display_name.to_string(),
            acl: AccessControlPolicy::from_canned(owner, display_name, CannedAcl::Private),
            default_object_acl,
        };
        let dir = layout::bucket_dir(&self.data_dir, name);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(io_err)?;
        atomic_write_json(&path, &info).await?;
        Ok(info)
    }

    /// Load bucket metadata or [`FlashError::NoSuchBucket`].
    pub async fn get_bucket(&self, name: &str) -> Result<BucketInfo, FlashError> {
        let path = layout::bucket_json_path(&self.data_dir, name);
        if !path.exists() {
            return Err(FlashError::NoSuchBucket);
        }
        read_json(&path).await
    }

    /// Delete an empty bucket (fails with [`FlashError::BucketNotEmpty`]).
    pub async fn delete_bucket(&self, name: &str) -> Result<(), FlashError> {
        let _ = self.get_bucket(name).await?;
        let count = self.index.count_in_bucket(name)?;
        if count > 0 {
            return Err(FlashError::BucketNotEmpty);
        }
        let dir = layout::bucket_dir(&self.data_dir, name);
        tokio::fs::remove_dir_all(dir).await.map_err(io_err)?;
        Ok(())
    }

    /// List all buckets under the data dir (sorted by name).
    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>, FlashError> {
        let root = self.data_dir.join("buckets");
        let mut out = Vec::new();
        let mut rd = tokio::fs::read_dir(&root).await.map_err(io_err)?;
        while let Some(entry) = rd.next_entry().await.map_err(io_err)? {
            if entry.file_type().await.map_err(io_err)?.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(info) = self.get_bucket(&name).await {
                    out.push(info);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub async fn put_bucket_acl(
        &self,
        name: &str,
        acl: AccessControlPolicy,
    ) -> Result<(), FlashError> {
        let mut info = self.get_bucket(name).await?;
        info.acl = acl;
        atomic_write_json(&layout::bucket_json_path(&self.data_dir, name), &info).await
    }

    pub async fn put_bucket_policy(&self, name: &str, raw: &str) -> Result<(), FlashError> {
        let _ = self.get_bucket(name).await?;
        let _ = BucketPolicy::parse_json(raw)?;
        atomic_write_bytes(&layout::bucket_policy_path(&self.data_dir, name), raw.as_bytes())
            .await
    }

    pub async fn get_bucket_policy(&self, name: &str) -> Result<String, FlashError> {
        let _ = self.get_bucket(name).await?;
        let path = layout::bucket_policy_path(&self.data_dir, name);
        if !path.exists() {
            return Err(FlashError::NoSuchBucketPolicy);
        }
        tokio::fs::read_to_string(path)
            .await
            .map_err(io_err)
    }

    pub async fn delete_bucket_policy(&self, name: &str) -> Result<(), FlashError> {
        let _ = self.get_bucket(name).await?;
        let path = layout::bucket_policy_path(&self.data_dir, name);
        if path.exists() {
            tokio::fs::remove_file(path).await.map_err(io_err)?;
        }
        Ok(())
    }

    pub async fn load_policy(&self, name: &str) -> Result<Option<BucketPolicy>, FlashError> {
        let path = layout::bucket_policy_path(&self.data_dir, name);
        if !path.exists() {
            return Ok(None);
        }
        let raw = tokio::fs::read_to_string(path).await.map_err(io_err)?;
        Ok(Some(BucketPolicy::parse_json(&raw)?))
    }

    pub async fn put_bucket_cors(&self, name: &str, raw_xml: &str) -> Result<(), FlashError> {
        let _ = self.get_bucket(name).await?;
        if raw_xml.len() > flash_s3_common::MAX_CORS_BYTES {
            return Err(FlashError::InvalidRequest(
                "CORS configuration exceeds 64 KiB".into(),
            ));
        }
        atomic_write_bytes(
            &layout::bucket_cors_path(&self.data_dir, name),
            raw_xml.as_bytes(),
        )
        .await
    }

    pub async fn get_bucket_cors(&self, name: &str) -> Result<String, FlashError> {
        let _ = self.get_bucket(name).await?;
        let path = layout::bucket_cors_path(&self.data_dir, name);
        if !path.exists() {
            return Err(FlashError::NoSuchCORSConfiguration);
        }
        tokio::fs::read_to_string(path).await.map_err(io_err)
    }

    pub async fn delete_bucket_cors(&self, name: &str) -> Result<(), FlashError> {
        let _ = self.get_bucket(name).await?;
        let path = layout::bucket_cors_path(&self.data_dir, name);
        if path.exists() {
            tokio::fs::remove_file(path).await.map_err(io_err)?;
        }
        Ok(())
    }

    /// Load raw CORS XML when present (caller parses).
    pub async fn load_cors_raw(&self, name: &str) -> Result<Option<String>, FlashError> {
        let path = layout::bucket_cors_path(&self.data_dir, name);
        if !path.exists() {
            return Ok(None);
        }
        let raw = tokio::fs::read_to_string(path).await.map_err(io_err)?;
        Ok(Some(raw))
    }

    /// Write-through put: atomic disk write, then index update.
    ///
    /// Callers decide whether to insert into the RAM cache afterwards.
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &ObjectKey,
        body: Bytes,
        opts: PutObjectOpts,
    ) -> Result<ObjectMeta, FlashError> {
        let _ = self.get_bucket(bucket).await?;
        let lock = self.lock_for(bucket, key.as_str());
        let _guard = lock.lock().await;
        let start = Instant::now();

        let current = layout::current_dir(&self.data_dir, bucket, key.as_str());
        tokio::fs::create_dir_all(&current)
            .await
            .map_err(io_err)?;

        let tmp = current.join(format!("data.{}.tmp", Uuid::new_v4()));
        {
            let mut f = tokio::fs::File::create(&tmp).await.map_err(io_err)?;
            f.write_all(&body).await.map_err(io_err)?;
            f.flush().await.map_err(io_err)?;
            f.sync_all().await.map_err(io_err)?;
        }
        let data_path = layout::data_path(&self.data_dir, bucket, key.as_str());
        tokio::fs::rename(&tmp, &data_path).await.map_err(io_err)?;

        let etag = md5_etag(&body);
        let acl = opts.acl.unwrap_or_else(|| {
            AccessControlPolicy::from_canned(
                opts.owner.clone(),
                &opts.owner_display_name,
                opts.canned_acl.unwrap_or(opts.default_object_acl),
            )
        });
        let meta = ObjectMeta {
            key: key.as_str().to_string(),
            size: body.len() as u64,
            etag: etag.clone(),
            content_type: opts
                .content_type
                .unwrap_or_else(|| "application/octet-stream".into()),
            content_encoding: opts.content_encoding,
            cache_control: opts.cache_control,
            content_disposition: opts.content_disposition,
            content_language: opts.content_language,
            expires: opts.expires,
            last_modified: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: opts.owner,
            owner_display_name: opts.owner_display_name,
            acl,
            user_meta: opts.user_meta,
            checksums: opts.checksums,
        };
        atomic_write_json(&layout::meta_path(&self.data_dir, bucket, key.as_str()), &meta)
            .await?;

        self.index.put(&IndexEntry {
            bucket: bucket.to_string(),
            key: key.as_str().to_string(),
            size: meta.size,
            etag: meta.etag.clone(),
            last_modified: meta.last_modified.clone(),
            content_type: meta.content_type.clone(),
        })?;

        self.metrics
            .disk_write_bytes
            .inc_by(body.len() as u64);
        self.metrics
            .disk_op_duration
            .with_label_values(&["write"])
            .observe(start.elapsed().as_secs_f64());
        Ok(meta)
    }

    /// Stream a large body to disk without buffering the entire object in RAM.
    pub async fn put_object_stream(
        &self,
        bucket: &str,
        key: &ObjectKey,
        mut reader: impl tokio::io::AsyncRead + Unpin,
        opts: PutObjectOpts,
    ) -> Result<ObjectMeta, FlashError> {
        use tokio::io::AsyncReadExt;
        let _ = self.get_bucket(bucket).await?;
        let lock = self.lock_for(bucket, key.as_str());
        let _guard = lock.lock().await;
        let start = Instant::now();

        let current = layout::current_dir(&self.data_dir, bucket, key.as_str());
        tokio::fs::create_dir_all(&current)
            .await
            .map_err(io_err)?;
        let tmp = current.join(format!("data.{}.tmp", Uuid::new_v4()));
        let mut hasher = Md5::new();
        let mut size = 0u64;
        let write_result: Result<(), FlashError> = async {
            let mut f = tokio::fs::File::create(&tmp).await.map_err(io_err)?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buf).await.map_err(io_err)?;
                if n == 0 {
                    break;
                }
                f.write_all(&buf[..n]).await.map_err(io_err)?;
                hasher.update(&buf[..n]);
                size += n as u64;
            }
            f.flush().await.map_err(io_err)?;
            f.sync_all().await.map_err(io_err)?;
            Ok(())
        }
        .await;
        if let Err(error) = write_result {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(error);
        }
        let data_path = layout::data_path(&self.data_dir, bucket, key.as_str());
        tokio::fs::rename(&tmp, &data_path).await.map_err(io_err)?;

        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        let acl = opts.acl.unwrap_or_else(|| {
            AccessControlPolicy::from_canned(
                opts.owner.clone(),
                &opts.owner_display_name,
                opts.canned_acl.unwrap_or(opts.default_object_acl),
            )
        });
        let meta = ObjectMeta {
            key: key.as_str().to_string(),
            size,
            etag: etag.clone(),
            content_type: opts
                .content_type
                .unwrap_or_else(|| "application/octet-stream".into()),
            content_encoding: opts.content_encoding,
            cache_control: opts.cache_control,
            content_disposition: opts.content_disposition,
            content_language: opts.content_language,
            expires: opts.expires,
            last_modified: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: opts.owner,
            owner_display_name: opts.owner_display_name,
            acl,
            user_meta: opts.user_meta,
            checksums: opts.checksums,
        };
        atomic_write_json(&layout::meta_path(&self.data_dir, bucket, key.as_str()), &meta)
            .await?;
        self.index.put(&IndexEntry {
            bucket: bucket.to_string(),
            key: key.as_str().to_string(),
            size: meta.size,
            etag: meta.etag.clone(),
            last_modified: meta.last_modified.clone(),
            content_type: meta.content_type.clone(),
        })?;
        self.metrics.disk_write_bytes.inc_by(size);
        self.metrics
            .disk_op_duration
            .with_label_values(&["write"])
            .observe(start.elapsed().as_secs_f64());
        Ok(meta)
    }

    pub async fn get_object_meta(
        &self,
        bucket: &str,
        key: &ObjectKey,
    ) -> Result<ObjectMeta, FlashError> {
        let _ = self.get_bucket(bucket).await?;
        let path = layout::meta_path(&self.data_dir, bucket, key.as_str());
        if !path.exists() {
            return Err(FlashError::NoSuchKey);
        }
        read_json(&path).await
    }

    /// Read a full object into memory (for small objects / cache fill).
    pub async fn read_object_bytes(
        &self,
        bucket: &str,
        key: &ObjectKey,
    ) -> Result<(ObjectMeta, Bytes), FlashError> {
        let start = Instant::now();
        let meta = self.get_object_meta(bucket, key).await?;
        let data = tokio::fs::read(layout::data_path(&self.data_dir, bucket, key.as_str()))
            .await
            .map_err(io_err)?;
        self.metrics.disk_read_bytes.inc_by(data.len() as u64);
        self.metrics
            .disk_op_duration
            .with_label_values(&["read"])
            .observe(start.elapsed().as_secs_f64());
        Ok((meta, Bytes::from(data)))
    }

    /// Open object body as an async file for streaming responses.
    pub async fn open_object_file(
        &self,
        bucket: &str,
        key: &ObjectKey,
    ) -> Result<(ObjectMeta, tokio::fs::File), FlashError> {
        let meta = self.get_object_meta(bucket, key).await?;
        let f = tokio::fs::File::open(layout::data_path(&self.data_dir, bucket, key.as_str()))
            .await
            .map_err(io_err)?;
        Ok((meta, f))
    }

    /// Open an object file positioned at `start` for a byte-range response.
    pub async fn open_object_range_file(
        &self,
        bucket: &str,
        key: &ObjectKey,
        start: u64,
    ) -> Result<tokio::fs::File, FlashError> {
        let mut file = tokio::fs::File::open(layout::data_path(&self.data_dir, bucket, key.as_str()))
            .await
            .map_err(io_err)?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(io_err)?;
        Ok(file)
    }

    pub async fn delete_object(&self, bucket: &str, key: &ObjectKey) -> Result<(), FlashError> {
        let _ = self.get_bucket(bucket).await?;
        let lock = self.lock_for(bucket, key.as_str());
        let _guard = lock.lock().await;
        let dir = layout::object_dir(&self.data_dir, bucket, key.as_str());
        if !dir.exists() {
            return Err(FlashError::NoSuchKey);
        }
        tokio::fs::remove_dir_all(dir).await.map_err(io_err)?;
        self.index.delete(bucket, key.as_str())?;
        self.metrics
            .disk_op_duration
            .with_label_values(&["delete"])
            .observe(0.0);
        Ok(())
    }

    pub async fn put_object_acl(
        &self,
        bucket: &str,
        key: &ObjectKey,
        acl: AccessControlPolicy,
    ) -> Result<(), FlashError> {
        let lock = self.lock_for(bucket, key.as_str());
        let _guard = lock.lock().await;
        let mut meta = self.get_object_meta(bucket, key).await?;
        meta.acl = acl;
        atomic_write_json(&layout::meta_path(&self.data_dir, bucket, key.as_str()), &meta).await
    }

    pub fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<(Vec<IndexEntry>, bool), FlashError> {
        let start = Instant::now();
        // ensure bucket exists synchronously via path check
        if !layout::bucket_json_path(&self.data_dir, bucket).exists() {
            return Err(FlashError::NoSuchBucket);
        }
        let res = self.index.list(bucket, prefix, start_after, max_keys)?;
        self.metrics
            .disk_op_duration
            .with_label_values(&["list"])
            .observe(start.elapsed().as_secs_f64());
        Ok(res)
    }

    pub async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &ObjectKey,
        dst_bucket: &str,
        dst_key: &ObjectKey,
        opts: PutObjectOpts,
    ) -> Result<ObjectMeta, FlashError> {
        let (_meta, file) = self.open_object_file(src_bucket, src_key).await?;
        self.put_object_stream(dst_bucket, dst_key, file, opts).await
    }

    // --- Multipart -----------------------------------------------------------

    /// Start a multipart upload and return the upload id.
    pub async fn create_multipart(
        &self,
        bucket: &str,
        key: &ObjectKey,
        owner: CanonicalUserId,
        display_name: &str,
        content_type: Option<String>,
        canned_acl: Option<CannedAcl>,
    ) -> Result<String, FlashError> {
        let _ = self.get_bucket(bucket).await?;
        let upload_id = Uuid::new_v4().to_string();
        let dir = layout::multipart_dir(&self.data_dir, bucket, &upload_id);
        tokio::fs::create_dir_all(&dir).await.map_err(io_err)?;
        let meta = MultipartMeta {
            upload_id: upload_id.clone(),
            key: key.as_str().to_string(),
            initiated: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner,
            owner_display_name: display_name.to_string(),
            content_type,
            canned_acl,
            parts: Vec::new(),
        };
        atomic_write_json(&dir.join("meta.json"), &meta).await?;
        self.metrics.multipart_inflight.inc();
        Ok(upload_id)
    }

    /// Store one multipart part; returns the part ETag.
    pub async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, FlashError> {
        if !(1..=10000).contains(&part_number) {
            return Err(FlashError::InvalidRequest("invalid part number".into()));
        }
        let part_lock = self.multipart_part_lock_for(bucket, upload_id, part_number);
        let _part_guard = part_lock.lock().await;
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let part_path = dir.join(format!("part-{part_number}"));
        atomic_write_bytes(&part_path, &body).await?;
        let etag = md5_etag(&body);
        self.commit_part(bucket, upload_id, part_number, etag.clone(), body.len() as u64)
            .await?;
        self.metrics.disk_write_bytes.inc_by(body.len() as u64);
        Ok(etag)
    }

    /// Stream one multipart part to disk, returning its ETag without buffering
    /// the whole part in memory.
    pub async fn upload_part_stream(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: i32,
        mut reader: impl tokio::io::AsyncRead + Unpin,
    ) -> Result<String, FlashError> {
        use tokio::io::AsyncReadExt;

        if !(1..=10000).contains(&part_number) {
            return Err(FlashError::InvalidRequest("invalid part number".into()));
        }
        let part_lock = self.multipart_part_lock_for(bucket, upload_id, part_number);
        let _part_guard = part_lock.lock().await;
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let part_path = dir.join(format!("part-{part_number}"));
        let tmp = part_path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut hasher = Md5::new();
        let mut size = 0u64;
        let write_result: Result<(), FlashError> = async {
            let mut file = tokio::fs::File::create(&tmp).await.map_err(io_err)?;
            let mut buffer = vec![0u8; 256 * 1024];
            loop {
                let read = reader.read(&mut buffer).await.map_err(io_err)?;
                if read == 0 {
                    break;
                }
                file.write_all(&buffer[..read]).await.map_err(io_err)?;
                hasher.update(&buffer[..read]);
                size += read as u64;
            }
            file.flush().await.map_err(io_err)?;
            file.sync_all().await.map_err(io_err)?;
            Ok(())
        }
        .await;
        if let Err(error) = write_result {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(error);
        }
        tokio::fs::rename(&tmp, &part_path).await.map_err(io_err)?;
        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        self.commit_part(bucket, upload_id, part_number, etag.clone(), size)
            .await?;
        self.metrics.disk_write_bytes.inc_by(size);
        Ok(etag)
    }

    /// Atomically add or replace a committed part in the upload manifest.
    async fn commit_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: i32,
        etag: String,
        size: u64,
    ) -> Result<(), FlashError> {
        let lock = self.multipart_lock_for(bucket, upload_id);
        let _guard = lock.lock().await;
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let mut meta: MultipartMeta = read_json(&meta_path).await?;
        meta.parts.retain(|p| p.part_number != part_number);
        meta.parts.push(MultipartPart {
            part_number,
            etag,
            size,
        });
        meta.parts.sort_by_key(|p| p.part_number);
        atomic_write_json(&meta_path, &meta).await
    }

    /// Concatenate parts in order into the final object and drop staging data.
    pub async fn complete_multipart(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[(i32, String)],
        default_object_acl: CannedAcl,
    ) -> Result<ObjectMeta, FlashError> {
        let multipart_lock = self.multipart_lock_for(bucket, upload_id);
        let _multipart_guard = multipart_lock.lock().await;
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let meta: MultipartMeta = read_json(&meta_path).await?;
        let key = ObjectKey::new(&meta.key).map_err(|_| FlashError::InvalidObjectName)?;
        if parts.is_empty() || parts.windows(2).any(|window| window[0].0 >= window[1].0) {
            return Err(FlashError::InvalidPartOrder);
        }
        let selected_parts = parts
            .iter()
            .enumerate()
            .map(|(index, (pn, etag))| {
                let stored = meta
                    .parts
                    .iter()
                    .find(|part| part.part_number == *pn)
                    .ok_or(FlashError::InvalidPart)?;
                if etag.trim_matches('"') != stored.etag.trim_matches('"') {
                    return Err(FlashError::InvalidPart);
                }
                if index + 1 != parts.len() && stored.size < 5 * 1024 * 1024 {
                    return Err(FlashError::EntityTooSmall);
                }
                Ok(stored.clone())
            })
            .collect::<Result<Vec<_>, FlashError>>()?;

        let lock = self.lock_for(bucket, key.as_str());
        let _guard = lock.lock().await;

        let current = layout::current_dir(&self.data_dir, bucket, key.as_str());
        tokio::fs::create_dir_all(&current)
            .await
            .map_err(io_err)?;
        let tmp = current.join(format!("data.{}.tmp", Uuid::new_v4()));
        let mut size = 0u64;
        let mut part_digests = Vec::with_capacity(selected_parts.len());
        let write_result: Result<(), FlashError> = async {
            let mut out = tokio::fs::File::create(&tmp).await.map_err(io_err)?;
            let mut buffer = vec![0u8; 256 * 1024];
            for stored in &selected_parts {
                let mut part = tokio::fs::File::open(
                    dir.join(format!("part-{}", stored.part_number)),
                )
                .await
                .map_err(io_err)?;
                loop {
                    let read = part.read(&mut buffer).await.map_err(io_err)?;
                    if read == 0 {
                        break;
                    }
                    out.write_all(&buffer[..read]).await.map_err(io_err)?;
                    size += read as u64;
                }
                let digest = hex::decode(stored.etag.trim_matches('"'))
                    .map_err(|_| FlashError::Internal("invalid stored multipart ETag".into()))?;
                if digest.len() != 16 {
                    return Err(FlashError::Internal("invalid stored multipart ETag".into()));
                }
                part_digests.extend_from_slice(&digest);
            }
            out.flush().await.map_err(io_err)?;
            out.sync_all().await.map_err(io_err)?;
            Ok(())
        }
        .await;
        if let Err(error) = write_result {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(error);
        }
        let data_path = layout::data_path(&self.data_dir, bucket, key.as_str());
        tokio::fs::rename(&tmp, &data_path).await.map_err(io_err)?;

        let etag = if selected_parts.len() > 1 {
            format!(
                "\"{}-{}\"",
                hex::encode(Md5::digest(&part_digests)),
                selected_parts.len()
            )
        } else {
            format!("\"{}\"", hex::encode(&part_digests))
        };

        let acl = AccessControlPolicy::from_canned(
            meta.owner.clone(),
            &meta.owner_display_name,
            meta.canned_acl.unwrap_or(default_object_acl),
        );
        let obj = ObjectMeta {
            key: key.as_str().to_string(),
            size,
            etag,
            content_type: meta
                .content_type
                .unwrap_or_else(|| "application/octet-stream".into()),
            content_encoding: None,
            cache_control: None,
            content_disposition: None,
            content_language: None,
            expires: None,
            last_modified: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: meta.owner,
            owner_display_name: meta.owner_display_name,
            acl,
            user_meta: Default::default(),
            checksums: Default::default(),
        };
        atomic_write_json(&layout::meta_path(&self.data_dir, bucket, key.as_str()), &obj)
            .await?;
        self.index.put(&IndexEntry {
            bucket: bucket.to_string(),
            key: key.as_str().to_string(),
            size: obj.size,
            etag: obj.etag.clone(),
            last_modified: obj.last_modified.clone(),
            content_type: obj.content_type.clone(),
        })?;
        tokio::fs::remove_dir_all(dir).await.map_err(io_err)?;
        self.metrics.multipart_inflight.dec();
        Ok(obj)
    }

    pub async fn abort_multipart(&self, bucket: &str, upload_id: &str) -> Result<(), FlashError> {
        let lock = self.multipart_lock_for(bucket, upload_id);
        let _guard = lock.lock().await;
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        if !dir.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        tokio::fs::remove_dir_all(dir).await.map_err(io_err)?;
        self.metrics.multipart_inflight.dec();
        Ok(())
    }

    pub async fn list_parts(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(String, Vec<(i32, String, u64)>), FlashError> {
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let meta: MultipartMeta = read_json(&meta_path).await?;
        let parts = meta
            .parts
            .into_iter()
            .map(|p| (p.part_number, p.etag, p.size))
            .collect();
        Ok((meta.key, parts))
    }
}

/// MD5 hex digest wrapped in quotes (S3 ETag style for single-part uploads).
fn md5_etag(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    format!("\"{}\"", hex::encode(h.finalize()))
}

fn io_err(e: std::io::Error) -> FlashError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        FlashError::InvalidRequest(e.to_string())
    } else {
        FlashError::Internal(e.to_string())
    }
}

/// Write `data` to `path` via temp file + fsync + rename (POSIX-atomic replace).
async fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), FlashError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_err)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    {
        let mut f = tokio::fs::File::create(&tmp).await.map_err(io_err)?;
        f.write_all(data).await.map_err(io_err)?;
        f.flush().await.map_err(io_err)?;
        f.sync_all().await.map_err(io_err)?;
    }
    tokio::fs::rename(&tmp, path).await.map_err(io_err)?;
    Ok(())
}

async fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), FlashError> {
    let data = serde_json::to_vec_pretty(value).map_err(|e| FlashError::Internal(e.to_string()))?;
    atomic_write_bytes(path, &data).await
}

async fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, FlashError> {
    let data = tokio::fs::read(path).await.map_err(io_err)?;
    serde_json::from_slice(&data).map_err(|e| FlashError::Internal(format!("corrupt meta: {e}")))
}
