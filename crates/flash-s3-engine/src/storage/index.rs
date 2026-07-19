use std::path::Path;
use std::sync::Arc;

use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};

use flash_s3_common::FlashError;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified: String,
    pub content_type: String,
}

#[derive(Clone)]
pub struct ObjectIndex {
    db: Arc<Database>,
}

impl ObjectIndex {
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

    pub fn list(
        &self,
        bucket: &str,
        prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<(Vec<IndexEntry>, bool), FlashError> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        let table = tx
            .open_table(TABLE)
            .map_err(|e| FlashError::Internal(e.to_string()))?;

        let prefix_key = format!("{bucket}\0{prefix}");
        let mut out = Vec::new();
        let mut truncated = false;
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
            if !object_key.starts_with(prefix) {
                // still might match if prefix empty; if prefix non-empty and doesn't start, stop when past prefix
                if !prefix.is_empty() && object_key > prefix && !object_key.starts_with(prefix) {
                    break;
                }
                if !prefix.is_empty() && !object_key.starts_with(prefix) {
                    continue;
                }
            }
            if let Some(sa) = start_after {
                if object_key <= sa {
                    continue;
                }
            }
            if out.len() >= max_keys {
                truncated = true;
                break;
            }
            let entry: IndexEntry = serde_json::from_slice(v.value())
                .map_err(|e| FlashError::Internal(e.to_string()))?;
            out.push(entry);
        }
        Ok((out, truncated))
    }

    pub fn count_in_bucket(&self, bucket: &str) -> Result<usize, FlashError> {
        let (entries, _) = self.list(bucket, "", None, usize::MAX)?;
        Ok(entries.len())
    }
}

fn io_err(e: std::io::Error) -> FlashError {
    FlashError::Internal(e.to_string())
}
