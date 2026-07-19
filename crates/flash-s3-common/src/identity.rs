use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Normalized S3 object key (no leading slash, no `..` segments).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectKey(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("empty key")]
    Empty,
    #[error("key contains invalid segment")]
    InvalidSegment,
    #[error("key too long")]
    TooLong,
}

impl ObjectKey {
    pub fn new(raw: impl AsRef<str>) -> Result<Self, KeyError> {
        let mut s = raw.as_ref().trim().to_string();
        while s.starts_with('/') {
            s.remove(0);
        }
        if s.is_empty() {
            return Err(KeyError::Empty);
        }
        if s.len() > 1024 {
            return Err(KeyError::TooLong);
        }
        for part in s.split('/') {
            if part == ".." || part == "." {
                return Err(KeyError::InvalidSegment);
            }
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Bucket name validation (S3-ish DNS rules, simplified).
pub fn validate_bucket_name(name: &str) -> Result<(), crate::FlashError> {
    let len = name.len();
    if !(3..=63).contains(&len) {
        return Err(crate::FlashError::InvalidBucketName);
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(crate::FlashError::InvalidBucketName);
    }
    if !bytes[len - 1].is_ascii_lowercase() && !bytes[len - 1].is_ascii_digit() {
        return Err(crate::FlashError::InvalidBucketName);
    }
    for b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.';
        if !ok {
            return Err(crate::FlashError::InvalidBucketName);
        }
    }
    if name.contains("..") || name.contains(".-") || name.contains("-.") {
        return Err(crate::FlashError::InvalidBucketName);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalUserId(String);

impl CanonicalUserId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CanonicalUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
