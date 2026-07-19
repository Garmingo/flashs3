use std::path::{Path, PathBuf};
use std::sync::Arc;

use flash_s3_common::{CanonicalUserId, FlashError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::layout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub access_key: String,
    pub secret_key: String,
    pub canonical_id: CanonicalUserId,
    pub display_name: String,
    pub is_root: bool,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CredentialsFile {
    keys: Vec<StoredKey>,
}

#[derive(Clone)]
pub struct CredentialStore {
    path: PathBuf,
    inner: Arc<RwLock<CredentialsFile>>,
}

impl CredentialStore {
    pub fn open(data_dir: &Path, bootstrap_access: Option<&str>, bootstrap_secret: Option<&str>) -> Result<Self, FlashError> {
        std::fs::create_dir_all(data_dir).map_err(|e| FlashError::Internal(e.to_string()))?;
        let path = layout::credentials_path(data_dir);
        let mut file = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| FlashError::Internal(e.to_string()))?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            CredentialsFile::default()
        };

        if file.keys.is_empty() {
            if let (Some(ak), Some(sk)) = (bootstrap_access, bootstrap_secret) {
                file.keys.push(make_key(ak, sk, "root", true));
            }
        }

        let store = Self {
            path,
            inner: Arc::new(RwLock::new(file)),
        };
        store.persist()?;
        Ok(store)
    }

    fn persist(&self) -> Result<(), FlashError> {
        let guard = self.inner.read();
        let data = serde_json::to_vec_pretty(&*guard)
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, data).map_err(|e| FlashError::Internal(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| FlashError::Internal(e.to_string()))?;
        Ok(())
    }

    pub fn get(&self, access_key: &str) -> Option<StoredKey> {
        self.inner
            .read()
            .keys
            .iter()
            .find(|k| k.access_key == access_key && k.status == KeyStatus::Active)
            .cloned()
    }

    pub fn list(&self) -> Vec<StoredKey> {
        self.inner.read().keys.clone()
    }

    pub fn create(
        &self,
        access_key: &str,
        secret_key: &str,
        display_name: &str,
        is_root: bool,
    ) -> Result<StoredKey, FlashError> {
        let mut guard = self.inner.write();
        if guard.keys.iter().any(|k| k.access_key == access_key) {
            return Err(FlashError::InvalidRequest("access key already exists".into()));
        }
        let key = make_key(access_key, secret_key, display_name, is_root);
        guard.keys.push(key.clone());
        drop(guard);
        self.persist()?;
        Ok(key)
    }

    pub fn disable(&self, access_key: &str) -> Result<(), FlashError> {
        let mut guard = self.inner.write();
        let key = guard
            .keys
            .iter_mut()
            .find(|k| k.access_key == access_key)
            .ok_or(FlashError::InvalidAccessKeyId)?;
        key.status = KeyStatus::Disabled;
        drop(guard);
        self.persist()
    }

    pub fn has_any_keys(&self) -> bool {
        !self.inner.read().keys.is_empty()
    }
}

fn make_key(access_key: &str, secret_key: &str, display_name: &str, is_root: bool) -> StoredKey {
    let mut h = Sha256::new();
    h.update(access_key.as_bytes());
    let canonical = CanonicalUserId::new(hex::encode(h.finalize()));
    StoredKey {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        canonical_id: canonical,
        display_name: display_name.to_string(),
        is_root,
        status: KeyStatus::Active,
    }
}
