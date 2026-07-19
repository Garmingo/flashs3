use std::path::{Path, PathBuf}; // PathBuf used by ObjectStore
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
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::metrics::Metrics;
use crate::storage::index::{IndexEntry, ObjectIndex};
use crate::storage::layout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    pub name: String,
    pub created: String,
    pub owner: CanonicalUserId,
    pub owner_display_name: String,
    pub acl: AccessControlPolicy,
    pub default_object_acl: CannedAcl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
    pub owner: CanonicalUserId,
    pub owner_display_name: String,
    pub acl: AccessControlPolicy,
    #[serde(default)]
    pub user_meta: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PutObjectOpts {
    pub content_type: Option<String>,
    pub canned_acl: Option<CannedAcl>,
    pub acl: Option<AccessControlPolicy>,
    pub owner: CanonicalUserId,
    pub owner_display_name: String,
    pub default_object_acl: CannedAcl,
    pub user_meta: std::collections::HashMap<String, String>,
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

#[derive(Clone)]
pub struct ObjectStore {
    data_dir: PathBuf,
    index: ObjectIndex,
    locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    metrics: Metrics,
}

impl ObjectStore {
    pub fn open(data_dir: PathBuf, metrics: Metrics) -> Result<Self, FlashError> {
        std::fs::create_dir_all(&data_dir).map_err(io_err)?;
        std::fs::create_dir_all(data_dir.join("buckets")).map_err(io_err)?;
        std::fs::create_dir_all(data_dir.join("index")).map_err(io_err)?;
        let index = ObjectIndex::open(&layout::index_path(&data_dir))?;
        Ok(Self {
            data_dir,
            index,
            locks: Arc::new(DashMap::new()),
            metrics,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

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

    pub async fn get_bucket(&self, name: &str) -> Result<BucketInfo, FlashError> {
        let path = layout::bucket_json_path(&self.data_dir, name);
        if !path.exists() {
            return Err(FlashError::NoSuchBucket);
        }
        read_json(&path).await
    }

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
            last_modified: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: opts.owner,
            owner_display_name: opts.owner_display_name,
            acl,
            user_meta: opts.user_meta,
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
        {
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
            last_modified: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: opts.owner,
            owner_display_name: opts.owner_display_name,
            acl,
            user_meta: opts.user_meta,
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
        let (_meta, bytes) = self.read_object_bytes(src_bucket, src_key).await?;
        self.put_object(dst_bucket, dst_key, bytes, opts).await
    }

    // --- Multipart ---

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
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let mut meta: MultipartMeta = read_json(&meta_path).await?;
        let part_path = dir.join(format!("part-{part_number}"));
        atomic_write_bytes(&part_path, &body).await?;
        let etag = md5_etag(&body);
        meta.parts.retain(|p| p.part_number != part_number);
        meta.parts.push(MultipartPart {
            part_number,
            etag: etag.clone(),
            size: body.len() as u64,
        });
        meta.parts.sort_by_key(|p| p.part_number);
        atomic_write_json(&meta_path, &meta).await?;
        self.metrics.disk_write_bytes.inc_by(body.len() as u64);
        Ok(etag)
    }

    pub async fn complete_multipart(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[(i32, String)],
        default_object_acl: CannedAcl,
    ) -> Result<ObjectMeta, FlashError> {
        let dir = layout::multipart_dir(&self.data_dir, bucket, upload_id);
        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            return Err(FlashError::NoSuchUpload);
        }
        let meta: MultipartMeta = read_json(&meta_path).await?;
        let key = ObjectKey::new(&meta.key).map_err(|_| FlashError::InvalidObjectName)?;

        let lock = self.lock_for(bucket, key.as_str());
        let _guard = lock.lock().await;

        let current = layout::current_dir(&self.data_dir, bucket, key.as_str());
        tokio::fs::create_dir_all(&current)
            .await
            .map_err(io_err)?;
        let tmp = current.join(format!("data.{}.tmp", Uuid::new_v4()));
        let mut hasher = Md5::new();
        let mut size = 0u64;
        let mut part_etags = Vec::new();
        {
            let mut out = tokio::fs::File::create(&tmp).await.map_err(io_err)?;
            for (pn, etag) in parts {
                let stored = meta
                    .parts
                    .iter()
                    .find(|p| p.part_number == *pn)
                    .ok_or(FlashError::InvalidPart)?;
                let want = etag.trim_matches('"');
                let have = stored.etag.trim_matches('"');
                if want != have {
                    return Err(FlashError::InvalidPart);
                }
                let bytes = tokio::fs::read(dir.join(format!("part-{pn}")))
                    .await
                    .map_err(io_err)?;
                out.write_all(&bytes).await.map_err(io_err)?;
                hasher.update(&bytes);
                size += bytes.len() as u64;
                part_etags.push(have.to_string());
            }
            out.flush().await.map_err(io_err)?;
            out.sync_all().await.map_err(io_err)?;
        }
        let data_path = layout::data_path(&self.data_dir, bucket, key.as_str());
        tokio::fs::rename(&tmp, &data_path).await.map_err(io_err)?;

        let etag = if part_etags.len() > 1 {
            format!(
                "\"{}-{}\"",
                hex::encode(hasher.finalize()),
                part_etags.len()
            )
        } else {
            format!("\"{}\"", hex::encode(hasher.finalize()))
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
            last_modified: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            owner: meta.owner,
            owner_display_name: meta.owner_display_name,
            acl,
            user_meta: Default::default(),
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

fn md5_etag(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    format!("\"{}\"", hex::encode(h.finalize()))
}

fn io_err(e: std::io::Error) -> FlashError {
    FlashError::Internal(e.to_string())
}

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
