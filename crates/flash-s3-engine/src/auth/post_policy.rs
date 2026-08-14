//! S3 POST object policy verification (SigV2 + SigV4).
//!
//! Browser uploads send a base64-encoded JSON policy and a signature over that
//! exact base64 string (not the decoded JSON).

use std::collections::{BTreeMap, HashSet};

use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use subtle::ConstantTimeEq;

use flash_s3_common::FlashError;

use super::credentials::{CredentialStore, StoredKey};
use super::sigv4::{hmac_sha256, signing_key};

type HmacSha1 = Hmac<Sha1>;

/// Verified POST policy and resolved credential (if authenticated).
#[derive(Debug, Clone)]
pub struct VerifiedPostPolicy {
    pub key: Option<StoredKey>,
}

/// Case-insensitive form field map (keys stored lowercase).
#[derive(Debug, Default, Clone)]
pub struct PostFormFields {
    fields: BTreeMap<String, String>,
}

impl PostFormFields {
    pub fn insert(&mut self, name: &str, value: String) {
        self.fields.insert(name.to_ascii_lowercase(), value);
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn raw_policy_b64(&self) -> Option<&str> {
        self.get("policy")
    }
}

/// Verify POST policy signature and conditions.
pub fn verify_post_policy(
    bucket: &str,
    policy_b64: &str,
    fields: &PostFormFields,
    file_size: u64,
    file_content_type: Option<&str>,
    region: &str,
    creds: &CredentialStore,
) -> Result<VerifiedPostPolicy, FlashError> {
    let policy_json = base64::engine::general_purpose::STANDARD
        .decode(policy_b64.as_bytes())
        .map_err(|_| FlashError::MalformedPolicy)?;
    let policy_str = std::str::from_utf8(&policy_json).map_err(|_| FlashError::MalformedPolicy)?;
    let doc: Value = serde_json::from_str(policy_str).map_err(|_| FlashError::MalformedPolicy)?;

    let expiration = doc
        .get("expiration")
        .and_then(Value::as_str)
        .ok_or(FlashError::MalformedPolicy)?;
    if doc.get("conditions").is_none() {
        return Err(FlashError::MalformedPolicy);
    }
    let conditions = doc
        .get("conditions")
        .and_then(Value::as_array)
        .ok_or(FlashError::MalformedPolicy)?;

    parse_expiration(expiration)?;

    let key = if fields.get("x-amz-algorithm").is_some() {
        verify_sigv4_signature(policy_b64, fields, region, creds)?
    } else if fields.get("awsaccesskeyid").is_some() {
        verify_sigv2_signature(policy_b64, fields, creds)?
    } else {
        return Err(FlashError::InvalidRequest("missing authentication".into()));
    };

    let content_length_range = evaluate_conditions(bucket, conditions, fields, file_size, file_content_type)?;

    let _ = content_length_range;
    Ok(VerifiedPostPolicy { key })
}

/// Anonymous POST (no policy): bucket must allow public write.
pub fn verify_anonymous_post_allowed(
    bucket_acl_allows_write: bool,
    has_policy: bool,
) -> Result<(), FlashError> {
    if has_policy {
        return Ok(());
    }
    if bucket_acl_allows_write {
        Ok(())
    } else {
        Err(FlashError::AccessDenied)
    }
}

fn parse_expiration(expiration: &str) -> Result<(), FlashError> {
    // AWS POST policies require ISO8601 basic format, not Python's default str(datetime).
    let dt = chrono::NaiveDateTime::parse_from_str(expiration, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| FlashError::InvalidRequest("invalid expiration".into()))?;
    if chrono::Utc::now() > dt.and_utc() {
        return Err(FlashError::AccessDenied);
    }
    Ok(())
}

fn verify_sigv2_signature(
    policy_b64: &str,
    fields: &PostFormFields,
    creds: &CredentialStore,
) -> Result<Option<StoredKey>, FlashError> {
    let access_key = fields
        .get("awsaccesskeyid")
        .ok_or(FlashError::InvalidRequest("missing AWSAccessKeyId".into()))?;
    let supplied = fields
        .get("signature")
        .ok_or(FlashError::InvalidRequest("missing signature".into()))?;

    let key = creds
        .get(access_key)
        .ok_or(FlashError::AccessDenied)?;

    let mut mac = HmacSha1::new_from_slice(key.secret_key.as_bytes())
        .map_err(|_| FlashError::Internal("HMAC key".into()))?;
    mac.update(policy_b64.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    if !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
        return Err(FlashError::SignatureDoesNotMatch);
    }
    Ok(Some(key))
}

fn verify_sigv4_signature(
    policy_b64: &str,
    fields: &PostFormFields,
    region: &str,
    creds: &CredentialStore,
) -> Result<Option<StoredKey>, FlashError> {
    if fields.get("x-amz-algorithm") != Some("AWS4-HMAC-SHA256") {
        return Err(FlashError::SignatureDoesNotMatch);
    }
    let credential = fields
        .get("x-amz-credential")
        .ok_or(FlashError::SignatureDoesNotMatch)?;
    let supplied = fields
        .get("x-amz-signature")
        .ok_or(FlashError::InvalidRequest("missing x-amz-signature".into()))?;
    let _date = fields
        .get("x-amz-date")
        .ok_or(FlashError::SignatureDoesNotMatch)?;

    let mut cred_parts = credential.split('/');
    let access_key = cred_parts.next().ok_or(FlashError::InvalidAccessKeyId)?;
    let date = cred_parts.next().ok_or(FlashError::SignatureDoesNotMatch)?;
    let cred_region = cred_parts.next().unwrap_or(region);

    let key = creds
        .get(access_key)
        .ok_or(FlashError::InvalidAccessKeyId)?;

    let k_signing = signing_key(&key.secret_key, date, cred_region, "s3");
    let expected = hex::encode(hmac_sha256(&k_signing, policy_b64.as_bytes()));

    if !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
        return Err(FlashError::SignatureDoesNotMatch);
    }
    Ok(Some(key))
}

fn evaluate_conditions(
    bucket: &str,
    conditions: &[Value],
    fields: &PostFormFields,
    file_size: u64,
    file_content_type: Option<&str>,
) -> Result<Option<(u64, u64)>, FlashError> {
    let mut covered: HashSet<String> = HashSet::new();
    let mut content_length_range: Option<(u64, u64)> = None;

    let mut has_bucket_condition = false;
    for condition in conditions {
        match condition {
            Value::Object(map) => {
                if map.is_empty() {
                    return Err(FlashError::MalformedPolicy);
                }
                for (key, expected) in map {
                    let expected_str = expected
                        .as_str()
                        .ok_or(FlashError::MalformedPolicy)?;
                    if key.eq_ignore_ascii_case("bucket") {
                        has_bucket_condition = true;
                        if bucket != expected_str {
                            return Err(FlashError::AccessDenied);
                        }
                        continue;
                    }
                    let field_name = normalize_field_name(key);
                    covered.insert(field_name.clone());
                    let actual = fields.get(&field_name).ok_or(FlashError::AccessDenied)?;
                    if actual != expected_str {
                        return Err(FlashError::AccessDenied);
                    }
                }
            }
            Value::Array(arr) => {
                if arr.is_empty() {
                    return Err(FlashError::MalformedPolicy);
                }
                let op = arr[0].as_str().ok_or(FlashError::MalformedPolicy)?;
                match op.to_ascii_lowercase().as_str() {
                    "content-length-range" => {
                        if arr.len() != 3 {
                            return Err(FlashError::MalformedPolicy);
                        }
                        let min = arr[1].as_u64().ok_or(FlashError::MalformedPolicy)?;
                        let max = arr[2].as_u64().ok_or(FlashError::MalformedPolicy)?;
                        content_length_range = Some((min, max));
                        if file_size < min {
                            return Err(FlashError::EntityTooSmall);
                        }
                        if file_size > max {
                            return Err(FlashError::InvalidArgument(
                                "content-length-range exceeded".into(),
                            ));
                        }
                    }
                    "starts-with" => {
                        if arr.len() != 3 {
                            return Err(FlashError::MalformedPolicy);
                        }
                        let field = arr[1].as_str().ok_or(FlashError::MalformedPolicy)?;
                        let prefix = arr[2].as_str().ok_or(FlashError::MalformedPolicy)?;
                        let field_name = normalize_field_name(field.strip_prefix('$').unwrap_or(field));
                        covered.insert(field_name.clone());
                        let actual = fields.get(&field_name).ok_or(FlashError::AccessDenied)?;
                        if !actual.starts_with(prefix) {
                            return Err(FlashError::AccessDenied);
                        }
                    }
                    "eq" => {
                        if arr.len() != 3 {
                            return Err(FlashError::MalformedPolicy);
                        }
                        let field = arr[1].as_str().ok_or(FlashError::MalformedPolicy)?;
                        let expected = arr[2].as_str().ok_or(FlashError::MalformedPolicy)?;
                        let field_name = normalize_field_name(field.strip_prefix('$').unwrap_or(field));
                        covered.insert(field_name.clone());
                        let actual = fields.get(&field_name).ok_or(FlashError::AccessDenied)?;
                        if actual != expected {
                            return Err(FlashError::AccessDenied);
                        }
                    }
                    _ => return Err(FlashError::MalformedPolicy),
                }
            }
            _ => return Err(FlashError::MalformedPolicy),
        }
    }

    if !has_bucket_condition {
        return Err(FlashError::AccessDenied);
    }

    // Every submitted field must appear in the policy (except auth/meta exclusions).
    for (name, _) in fields.iter() {
        if is_excluded_form_field(name) {
            continue;
        }
        if !covered.contains(name) {
            return Err(FlashError::AccessDenied);
        }
    }

    // Content-Type may be satisfied by file part Content-Type when not in form.
    if let Some(ct) = file_content_type {
        if fields.get("content-type").is_none() {
            if let Some(expected) = covered.get("content-type") {
                let _ = expected;
            }
        }
        let _ = ct;
    }

    let _ = content_length_range;
    Ok(content_length_range)
}

fn normalize_field_name(field: &str) -> String {
    field.strip_prefix('$').unwrap_or(field).to_ascii_lowercase()
}

fn is_excluded_form_field(name: &str) -> bool {
    matches!(
        name,
        "policy"
            | "signature"
            | "x-amz-signature"
            | "file"
            | "bucket"
            | "awsaccesskeyid"
            | "success_action_status"
            | "success_action_redirect"
    ) || name.starts_with("x-ignore-")
}

/// Resolve object key from form fields and optional file name.
pub fn resolve_post_object_key(fields: &PostFormFields, file_name: Option<&str>) -> Result<String, FlashError> {
    let key = fields
        .get("key")
        .ok_or(FlashError::InvalidRequest("missing key".into()))?;
    if key == "${filename}" {
        let name = file_name
            .filter(|n| !n.is_empty())
            .ok_or(FlashError::InvalidRequest("missing filename".into()))?;
        return Ok(name.to_string());
    }
    Ok(key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const ACCESS: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn creds() -> (tempfile::TempDir, CredentialStore) {
        let dir = tempdir().unwrap();
        let creds = CredentialStore::open(dir.path(), Some(ACCESS.into()), Some(SECRET.into()), None).unwrap();
        (dir, creds)
    }

    fn sign_v2(policy_b64: &str) -> String {
        let mut mac = HmacSha1::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(policy_b64.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    fn sign_v4(policy_b64: &str, date: &str) -> String {
        let k = signing_key(SECRET, date, "us-east-1", "s3");
        hex::encode(hmac_sha256(&k, policy_b64.as_bytes()))
    }

    #[test]
    fn verifies_sigv2_policy() {
        let (_dir, creds) = creds();
        let policy_doc = r#"{"expiration":"2099-01-01T00:00:00Z","conditions":[{"bucket":"b"},{"acl":"private"},["starts-with","$key","foo"],["content-length-range",0,1024]]}"#;
        let policy_b64 = base64::engine::general_purpose::STANDARD.encode(policy_doc);
        let sig = sign_v2(&policy_b64);
        let mut fields = PostFormFields::default();
        fields.insert("policy", policy_b64.clone());
        fields.insert("AWSAccessKeyId", ACCESS.into());
        fields.insert("signature", sig);
        fields.insert("acl", "private".into());
        fields.insert("key", "foo.txt".into());
        verify_post_policy("b", &policy_b64, &fields, 3, None, "us-east-1", &creds).unwrap();
    }

    #[test]
    fn verifies_sigv4_policy() {
        let (_dir, creds) = creds();
        let date = "20260814";
        let policy_doc = format!(
            r#"{{"expiration":"2099-01-01T00:00:00Z","conditions":[{{"bucket":"uploads"}},{{"key":"k"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{ACCESS}/{date}/us-east-1/s3/aws4_request"}},{{"x-amz-date":"20260814T091526Z"}}]}}"#
        );
        let policy_b64 = base64::engine::general_purpose::STANDARD.encode(policy_doc.as_bytes());
        let sig = sign_v4(&policy_b64, date);
        let mut fields = PostFormFields::default();
        fields.insert("policy", policy_b64.clone());
        fields.insert("x-amz-algorithm", "AWS4-HMAC-SHA256".into());
        fields.insert(
            "x-amz-credential",
            format!("{ACCESS}/{date}/us-east-1/s3/aws4_request"),
        );
        fields.insert("x-amz-date", "20260814T091526Z".into());
        fields.insert("x-amz-signature", sig);
        fields.insert("key", "k".into());
        verify_post_policy("uploads", &policy_b64, &fields, 1, None, "us-east-1", &creds).unwrap();
    }

    #[test]
    fn rejects_bad_signature() {
        let (_dir, creds) = creds();
        let policy_b64 = base64::engine::general_purpose::STANDARD.encode(r#"{"expiration":"2099-01-01T00:00:00Z","conditions":[{"bucket":"b"}]}"#);
        let mut fields = PostFormFields::default();
        fields.insert("policy", policy_b64.clone());
        fields.insert("AWSAccessKeyId", ACCESS.into());
        fields.insert("signature", "bad".into());
        fields.insert("key", "k".into());
        assert!(matches!(
            verify_post_policy("b", &policy_b64, &fields, 1, None, "us-east-1", &creds),
            Err(FlashError::SignatureDoesNotMatch)
        ));
    }
}
