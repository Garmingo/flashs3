//! redb-backed key index for fast ListObjects without walking the filesystem.
//!
//! Keys are stored as `"{bucket}\0{objectKey}"` so range scans stay per-bucket.
//! The index is rebuildable from disk if corrupted (rebuild not yet automated).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};

use flash_s3_common::FlashError;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");

/// Lightweight listing metadata mirrored from object `meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// Quoted MD5 ETag.
    pub etag: String,
    /// RFC3339 timestamp.
    pub last_modified: String,
    /// MIME type.
    pub content_type: String,
}

/// Result of a ListObjects-style index scan.
#[derive(Debug, Clone, Default)]
pub struct ObjectListResult {
    /// Matching object keys (not rolled into a common prefix).
    pub contents: Vec<IndexEntry>,
    /// Unique common prefixes when a delimiter is set.
    pub common_prefixes: Vec<String>,
    /// True when more results exist beyond `max_keys` combined slots.
    pub truncated: bool,
    /// Continuation key for the next page (last emitted content or prefix).
    pub next_token: Option<String>,
}

/// Embedded key/value index (`objects.redb`).
#[derive(Clone)]
pub struct ObjectIndex {
    db: Arc<Database>,
}

impl ObjectIndex {
    /// Open or create the index database at `path`.
    pub fn open(path: &Path) -> Result<Self, FlashError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let db = Database::create(path).map_err(|e| FlashError::Internal(e.to_string()))?;
        {
            let tx = db.begin_write().map_err(|e| FlashError::Internal(e.to_string()))?;
            {
                let _ = tx.open_table(TABLE).map_err(|e| FlashError::Internal(e.to_string()))?;
            }
            tx.commit().map_err(|e| FlashError::Internal(e.to_string()))?;
        }
        Ok(Self { db: Arc::new(db) })
    }

    fn compound_key(bucket: &str, key: &str) -> String {
        format!("{bucket}\0{key}")
    }

    /// Insert or update an object listing entry.
    pub fn put(&self, entry: &IndexEntry) -> Result<(), FlashError> {
        let k = Self::compound_key(&entry.bucket, &entry.key);
        let v = serde_json::to_vec(entry).map_err(|e| FlashError::Internal(e.to_string()))?;
        let tx = self
            .db
            .begin_write()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        {
            let mut table = tx
                .open_table(TABLE)
                .map_err(|e| FlashError::Internal(e.to_string()))?;
            table
                .insert(k.as_str(), v.as_slice())
                .map_err(|e| FlashError::Internal(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Remove an object from the listing index.
    pub fn delete(&self, bucket: &str, key: &str) -> Result<(), FlashError> {
        let k = Self::compound_key(bucket, key);
        let tx = self
            .db
            .begin_write()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        {
            let mut table = tx
                .open_table(TABLE)
                .map_err(|e| FlashError::Internal(e.to_string()))?;
            let _ = table
                .remove(k.as_str())
                .map_err(|e| FlashError::Internal(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Lookup a single listing entry (unused by hot path; kept for rebuild/tools).
    #[allow(dead_code)]
    pub fn get(&self, bucket: &str, key: &str) -> Result<Option<IndexEntry>, FlashError> {
        let k = Self::compound_key(bucket, key);
        let tx = self
            .db
            .begin_read()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        let table = tx
            .open_table(TABLE)
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        match table
            .get(k.as_str())
            .map_err(|e| FlashError::Internal(e.to_string()))?
        {
            Some(v) => {
                let entry: IndexEntry = serde_json::from_slice(v.value())
                    .map_err(|e| FlashError::Internal(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// List objects in `bucket` with optional prefix / delimiter / pagination.
    pub fn list(
        &self,
        bucket: &str,
        prefix: &str,
        start_after: Option<&str>,
        delimiter: Option<&str>,
        max_keys: usize,
    ) -> Result<ObjectListResult, FlashError> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        let table = tx
            .open_table(TABLE)
            .map_err(|e| FlashError::Internal(e.to_string()))?;

        let prefix_key = format!("{bucket}\0{prefix}");
        let mut contents = Vec::new();
        let mut common_prefixes = Vec::new();
        let mut seen_prefixes: BTreeSet<String> = BTreeSet::new();
        let mut truncated = false;
        let mut next_token = None;
        let mut slots = 0usize;

        let iter = table
            .range(prefix_key.as_str()..)
            .map_err(|e| FlashError::Internal(e.to_string()))?;

        for item in iter {
            let (k, v) = item.map_err(|e| FlashError::Internal(e.to_string()))?;
            let key_str = k.value();
            if !key_str.starts_with(&format!("{bucket}\0")) {
                break;
            }
            let object_key = &key_str[bucket.len() + 1..];
            if !prefix.is_empty() && !object_key.starts_with(prefix) {
                if object_key > prefix {
                    break;
                }
                continue;
            }
            if let Some(sa) = start_after {
                if object_key <= sa {
                    continue;
                }
            }

            let entry: IndexEntry = serde_json::from_slice(v.value())
                .map_err(|e| FlashError::Internal(e.to_string()))?;

            if let Some(delim) = delimiter.filter(|d| !d.is_empty()) {
                let rest = &object_key[prefix.len()..];
                if let Some(pos) = rest.find(delim) {
                    let cp = format!("{}{}", prefix, &rest[..=pos]);
                    if let Some(sa) = start_after {
                        if cp.as_str() <= sa {
                            continue;
                        }
                    }
                    if seen_prefixes.contains(&cp) {
                        continue;
                    }
                    if slots >= max_keys {
                        truncated = true;
                        next_token = Some(cp);
                        break;
                    }
                    seen_prefixes.insert(cp.clone());
                    common_prefixes.push(cp.clone());
                    slots += 1;
                    next_token = Some(cp);
                    continue;
                }
            }

            if slots >= max_keys {
                truncated = true;
                next_token = Some(object_key.to_string());
                break;
            }
            next_token = Some(object_key.to_string());
            contents.push(entry);
            slots += 1;
        }

        if !truncated {
            next_token = None;
        }

        Ok(ObjectListResult {
            contents,
            common_prefixes,
            truncated,
            next_token,
        })
    }

    /// Count indexed objects in a bucket (used by `DeleteBucket`).
    pub fn count_in_bucket(&self, bucket: &str) -> Result<usize, FlashError> {
        let result = self.list(bucket, "", None, None, usize::MAX)?;
        Ok(result.contents.len())
    }
}

fn io_err(e: std::io::Error) -> FlashError {
    FlashError::Internal(e.to_string())
}
