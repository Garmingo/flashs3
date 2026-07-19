//! Local multi-key credential store (`credentials.json` under the data dir).
//!
//! # At-rest encryption
//!
//! - Without [`flash_s3_common::ENV_CREDENTIALS_KEY`]: secrets are stored in plaintext.
//! - With the env var set: each `secret_key` is persisted as AES-256-GCM
//!   (`enc:v1:<base64(nonce||ciphertext)>`). In memory secrets remain plaintext
//!   for SigV4 HMAC.
//!
//! The AES key is `SHA-256(FLASHS3_CREDENTIALS_KEY)`. Losing the credentials key
//! makes existing encrypted secrets unrecoverable.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use flash_s3_common::{CanonicalUserId, FlashError};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::layout;

const ENC_PREFIX: &str = "enc:v1:";
const NONCE_LEN: usize = 12;

/// One API key pair usable for SigV4.
///
/// `secret_key` is always **plaintext in memory**. On disk it may be encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    /// Public access key id.
    pub access_key: String,
    /// Secret used for HMAC signing (plaintext while loaded).
    pub secret_key: String,
    /// Stable id for ACL owner/grantee fields.
    pub canonical_id: CanonicalUserId,
    /// Human-readable name.
    pub display_name: String,
    /// Root keys can bypass ACL/policy when configured.
    pub is_root: bool,
    /// Active keys may authenticate; disabled keys are rejected.
    pub status: KeyStatus,
}

/// Whether a key may be used for authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// Usable for SigV4.
    Active,
    /// Rejected at auth time.
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CredentialsFile {
    keys: Vec<StoredKey>,
}

/// Thread-safe credential store persisted as JSON.
#[derive(Clone)]
pub struct CredentialStore {
    path: PathBuf,
    inner: Arc<RwLock<CredentialsFile>>,
    /// When set, secrets are encrypted on disk with AES-256-GCM.
    master_key: Option<[u8; 32]>,
}

impl CredentialStore {
    /// Load `credentials.json`, bootstrapping a root key from env if empty.
    ///
    /// `credentials_key` is the optional at-rest master passphrase
    /// (`FLASHS3_CREDENTIALS_KEY`).
    pub fn open(
        data_dir: &Path,
        bootstrap_access: Option<&str>,
        bootstrap_secret: Option<&str>,
        credentials_key: Option<&str>,
    ) -> Result<Self, FlashError> {
        std::fs::create_dir_all(data_dir).map_err(|e| FlashError::Internal(e.to_string()))?;
        let path = layout::credentials_path(data_dir);
        let master_key = credentials_key.map(derive_master_key);

        let mut file = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| FlashError::Internal(e.to_string()))?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            CredentialsFile::default()
        };

        // Decrypt any on-disk secrets into plaintext for in-memory use.
        for key in &mut file.keys {
            key.secret_key = decode_secret(&key.secret_key, master_key.as_ref())?;
        }

        if file.keys.is_empty() {
            if let (Some(ak), Some(sk)) = (bootstrap_access, bootstrap_secret) {
                file.keys.push(make_key(ak, sk, "root", true));
            }
        }

        let store = Self {
            path,
            inner: Arc::new(RwLock::new(file)),
            master_key,
        };
        store.persist()?;
        Ok(store)
    }

    fn persist(&self) -> Result<(), FlashError> {
        let guard = self.inner.read();
        let mut disk = CredentialsFile {
            keys: guard.keys.clone(),
        };
        for key in &mut disk.keys {
            key.secret_key = encode_secret(&key.secret_key, self.master_key.as_ref())?;
        }
        let data = serde_json::to_vec_pretty(&disk)
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &data).map_err(|e| FlashError::Internal(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| FlashError::Internal(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Whether secrets are encrypted when written to disk.
    pub fn encryption_enabled(&self) -> bool {
        self.master_key.is_some()
    }

    /// Lookup an active key by access key id.
    pub fn get(&self, access_key: &str) -> Option<StoredKey> {
        self.inner
            .read()
            .keys
            .iter()
            .find(|k| k.access_key == access_key && k.status == KeyStatus::Active)
            .cloned()
    }

    /// Return all keys (including disabled).
    pub fn list(&self) -> Vec<StoredKey> {
        self.inner.read().keys.clone()
    }

    /// Create a new key; fails if the access key already exists.
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

    /// Mark a key disabled without deleting it.
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

    /// True if at least one key exists (used to decide whether anon is allowed).
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

fn derive_master_key(passphrase: &str) -> [u8; 32] {
    let digest = Sha256::digest(passphrase.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn encode_secret(plaintext: &str, master: Option<&[u8; 32]>) -> Result<String, FlashError> {
    let Some(key) = master else {
        return Ok(plaintext.to_string());
    };
    // Already encrypted (shouldn't happen for in-memory plaintext) — leave as-is.
    if plaintext.starts_with(ENC_PREFIX) {
        return Ok(plaintext.to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| FlashError::Internal(format!("aes key: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| FlashError::Internal(format!("encrypt secret: {e}")))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{ENC_PREFIX}{}", B64.encode(blob)))
}

fn decode_secret(stored: &str, master: Option<&[u8; 32]>) -> Result<String, FlashError> {
    if let Some(rest) = stored.strip_prefix(ENC_PREFIX) {
        let Some(key) = master else {
            return Err(FlashError::Internal(
                "credentials.json contains encrypted secrets but FLASHS3_CREDENTIALS_KEY is not set"
                    .into(),
            ));
        };
        let blob = B64
            .decode(rest)
            .map_err(|e| FlashError::Internal(format!("bad enc secret: {e}")))?;
        if blob.len() <= NONCE_LEN {
            return Err(FlashError::Internal("truncated enc secret".into()));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| FlashError::Internal(format!("aes key: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plain = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| FlashError::Internal(
                "failed to decrypt credential secret (wrong FLASHS3_CREDENTIALS_KEY?)".into(),
            ))?;
        String::from_utf8(plain).map_err(|e| FlashError::Internal(e.to_string()))
    } else {
        // Plaintext on disk — fine with or without master key (will encrypt on next persist).
        Ok(stored.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = derive_master_key("test-master-secret");
        let enc = encode_secret("flashsecret", Some(&key)).unwrap();
        assert!(enc.starts_with(ENC_PREFIX));
        assert_ne!(enc, "flashsecret");
        let dec = decode_secret(&enc, Some(&key)).unwrap();
        assert_eq!(dec, "flashsecret");
    }

    #[test]
    fn plaintext_passthrough_without_master() {
        let enc = encode_secret("plain", None).unwrap();
        assert_eq!(enc, "plain");
        let dec = decode_secret("plain", None).unwrap();
        assert_eq!(dec, "plain");
    }

    #[test]
    fn encrypted_requires_master() {
        let key = derive_master_key("k");
        let enc = encode_secret("s", Some(&key)).unwrap();
        assert!(decode_secret(&enc, None).is_err());
    }

    #[test]
    fn persist_encrypted_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CredentialStore::open(
            tmp.path(),
            Some("flash"),
            Some("flashsecret"),
            Some("master-key-xyz"),
        )
        .unwrap();
        assert!(store.encryption_enabled());
        let raw = std::fs::read_to_string(tmp.path().join("credentials.json")).unwrap();
        assert!(raw.contains(ENC_PREFIX));
        assert!(!raw.contains("flashsecret"));

        // Reload with same master key
        let store2 =
            CredentialStore::open(tmp.path(), None, None, Some("master-key-xyz")).unwrap();
        let k = store2.get("flash").unwrap();
        assert_eq!(k.secret_key, "flashsecret");
    }
}
