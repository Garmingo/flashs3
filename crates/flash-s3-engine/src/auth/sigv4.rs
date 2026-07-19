//! AWS Signature Version 4 verification (header auth + presigned query).
//!
//! Supports both `Authorization: AWS4-HMAC-SHA256 …` and query-string
//! presigned URLs (`X-Amz-Signature`, …). Payload hashing follows the
//! `x-amz-content-sha256` header when present.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use flash_s3_common::FlashError;

use super::credentials::{CredentialStore, StoredKey};

type HmacSha256 = Hmac<Sha256>;

/// Successful SigV4 authentication result.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Resolved credential used to sign the request.
    pub key: StoredKey,
}

/// Verify SigV4 for an incoming request.
///
/// Returns:
/// - `Ok(Some(_))` when a valid signature was present
/// - `Ok(None)` when the request is anonymous (no auth material)
/// - `Err(_)` on malformed or invalid signatures
pub fn verify_request(
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    payload_hash: &str,
    region: &str,
    creds: &CredentialStore,
) -> Result<Option<AuthResult>, FlashError> {
    // Presigned query auth
    if query.contains_key("X-Amz-Signature") {
        return verify_presigned(method, path, query, headers, region, creds);
    }

    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(a) if a.starts_with("AWS4-HMAC-SHA256 ") => a,
        Some(_) => return Err(FlashError::SignatureDoesNotMatch),
        None => return Ok(None),
    };

    let rest = &auth["AWS4-HMAC-SHA256 ".len()..];
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = Some(v);
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v);
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v);
        }
    }
    let credential = credential.ok_or(FlashError::SignatureDoesNotMatch)?;
    let signed_headers = signed_headers.ok_or(FlashError::SignatureDoesNotMatch)?;
    let signature = signature.ok_or(FlashError::SignatureDoesNotMatch)?;

    let mut cred_parts = credential.split('/');
    let access_key = cred_parts.next().ok_or(FlashError::InvalidAccessKeyId)?;
    let date = cred_parts.next().ok_or(FlashError::SignatureDoesNotMatch)?;
    let cred_region = cred_parts.next().unwrap_or(region);
    let _ = cred_parts.next(); // s3
    let _ = cred_parts.next(); // aws4_request

    let key = creds
        .get(access_key)
        .ok_or(FlashError::InvalidAccessKeyId)?;

    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or(FlashError::SignatureDoesNotMatch)?;

    let canonical_headers = build_canonical_headers(headers, signed_headers)?;
    let canonical_query = canonical_query_string(query);
    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let scope = format!("{date}/{cred_region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    let expected = signing_signature(&key.secret_key, date, cred_region, "s3", &string_to_sign);
    if !bool::from(expected.as_bytes().ct_eq(signature.as_bytes())) {
        return Err(FlashError::SignatureDoesNotMatch);
    }
    Ok(Some(AuthResult { key }))
}

fn verify_presigned(
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    region: &str,
    creds: &CredentialStore,
) -> Result<Option<AuthResult>, FlashError> {
    let credential = query
        .get("X-Amz-Credential")
        .ok_or(FlashError::SignatureDoesNotMatch)?;
    let signed_headers = query
        .get("X-Amz-SignedHeaders")
        .ok_or(FlashError::SignatureDoesNotMatch)?;
    let signature = query
        .get("X-Amz-Signature")
        .ok_or(FlashError::SignatureDoesNotMatch)?;
    let amz_date = query
        .get("X-Amz-Date")
        .ok_or(FlashError::SignatureDoesNotMatch)?;
    let expires: i64 = query
        .get("X-Amz-Expires")
        .and_then(|e| e.parse().ok())
        .unwrap_or(0);

    // Expiry check (best-effort)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        let signed_at = dt.and_utc();
        let now = chrono::Utc::now();
        if now > signed_at + chrono::Duration::seconds(expires) {
            return Err(FlashError::AccessDenied);
        }
    }

    let mut cred_parts = credential.split('/');
    let access_key = cred_parts.next().ok_or(FlashError::InvalidAccessKeyId)?;
    let date = cred_parts.next().ok_or(FlashError::SignatureDoesNotMatch)?;
    let cred_region = cred_parts.next().unwrap_or(region);

    let key = creds
        .get(access_key)
        .ok_or(FlashError::InvalidAccessKeyId)?;

    let mut q = query.clone();
    q.remove("X-Amz-Signature");
    let canonical_query = canonical_query_string(&q);
    let payload_hash = query
        .get("X-Amz-Content-Sha256")
        .map(|s| s.as_str())
        .unwrap_or("UNSIGNED-PAYLOAD");
    let canonical_headers = build_canonical_headers(headers, signed_headers)?;
    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let scope = format!("{date}/{cred_region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");
    let expected = signing_signature(&key.secret_key, date, cred_region, "s3", &string_to_sign);
    if !bool::from(expected.as_bytes().ct_eq(signature.as_bytes())) {
        return Err(FlashError::SignatureDoesNotMatch);
    }
    Ok(Some(AuthResult { key }))
}

fn build_canonical_headers(headers: &HeaderMap, signed: &str) -> Result<String, FlashError> {
    let mut out = String::new();
    for name in signed.split(';') {
        let value = headers
            .get(name)
            .or_else(|| {
                // host often required
                if name == "host" {
                    headers.get(http::header::HOST)
                } else {
                    None
                }
            })
            .and_then(|v| v.to_str().ok())
            .ok_or(FlashError::SignatureDoesNotMatch)?;
        let collapsed = collapse_ws(value);
        out.push_str(name);
        out.push(':');
        out.push_str(&collapsed);
        out.push('\n');
    }
    Ok(out)
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::new();
    let mut last_space = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out
}

fn canonical_query_string(query: &BTreeMap<String, String>) -> String {
    query
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn signing_signature(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> String {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Hex-encoded SHA-256 of the request payload (SigV4 payload hash).
pub fn hash_payload(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}
