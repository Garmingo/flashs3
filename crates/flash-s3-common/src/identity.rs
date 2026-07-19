//! Bucket/object identity helpers and validation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Normalized S3 object key (no leading slash, no `.` / `..` segments).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectKey(String);

/// Why [`ObjectKey::new`] rejected a raw key string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    /// Empty after trimming/stripping slashes.
    #[error("empty key")]
    Empty,
    /// Contained `.` or `..` path segments.
    #[error("key contains invalid segment")]
    InvalidSegment,
    /// Longer than 1024 bytes.
    #[error("key too long")]
    TooLong,
}

impl ObjectKey {
    /// Validate and normalize a client-supplied object key.
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

    /// Borrow the normalized key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate a bucket name against simplified S3 DNS naming rules.
///
/// Rules: 3–63 chars, lowercase alnum / `-` / `.`, must start and end with
/// alnum, no `..`, `.-`, or `-.`.
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

/// Stable identity used as ACL owner / grantee (`CanonicalUser`).
///
/// Derived from the access key at credential creation time (SHA-256 hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalUserId(String);

impl CanonicalUserId {
    /// Wrap an existing id string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the id bytes as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CanonicalUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlashError;

    #[test]
    fn object_key_strips_leading_slashes() {
        let k = ObjectKey::new("/foo/bar").unwrap();
        assert_eq!(k.as_str(), "foo/bar");
    }

    #[test]
    fn object_key_rejects_dot_segments() {
        assert_eq!(ObjectKey::new("a/../b").unwrap_err(), KeyError::InvalidSegment);
        assert_eq!(ObjectKey::new(".").unwrap_err(), KeyError::InvalidSegment);
        assert_eq!(ObjectKey::new("").unwrap_err(), KeyError::Empty);
    }

    #[test]
    fn object_key_rejects_too_long() {
        let s = "a".repeat(1025);
        assert_eq!(ObjectKey::new(&s).unwrap_err(), KeyError::TooLong);
    }

    #[test]
    fn bucket_name_validation() {
        assert!(validate_bucket_name("demo").is_ok());
        assert!(validate_bucket_name("my-bucket.1").is_ok());
        assert_eq!(
            validate_bucket_name("Ab"),
            Err(FlashError::InvalidBucketName)
        );
        assert_eq!(
            validate_bucket_name("a..b"),
            Err(FlashError::InvalidBucketName)
        );
        assert_eq!(
            validate_bucket_name("-bad"),
            Err(FlashError::InvalidBucketName)
        );
    }
}
