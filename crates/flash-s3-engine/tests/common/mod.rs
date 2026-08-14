//! Shared helpers for flash-s3-engine integration tests.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::Bytes;
use chrono::Utc;
use flash_s3_engine::api::router;
use flash_s3_engine::{AppState, Config};
use hex;
use hmac::{Hmac, Mac};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use axum::body::Body;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

static PORT: AtomicU16 = AtomicU16::new(19_000);

pub const ACCESS: &str = "flash";
pub const SECRET: &str = "flashsecret";
pub const REGION: &str = "us-east-1";

pub fn test_config(data_dir: PathBuf) -> Config {
    Config {
        data_dir,
        bind: format!("127.0.0.1:{}", PORT.fetch_add(1, Ordering::SeqCst)),
        cache_policy: "InMemoryLRU".into(),
        cache_max_bytes: 64 * 1024 * 1024,
        cache_object_max_bytes: 4 * 1024 * 1024,
        access_key: Some(ACCESS.into()),
        secret_key: Some(SECRET.into()),
        credentials_key: None,
        region: REGION.into(),
        auth_required: false,
        default_object_acl: "private".into(),
        default_bucket_name: None,
        default_bucket_cors: None,
        default_bucket_cors_allow_all: false,
        root_bypasses_acl: true,
        sse_s3_key: None,
        virtual_host_base: None,
    }
}

pub fn app_state(tmp: &tempfile::TempDir) -> AppState {
    AppState::new(test_config(tmp.path().to_path_buf())).expect("app state")
}

pub fn uri_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn sign_headers(
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: &[u8],
    host: &str,
) -> Vec<(String, String)> {
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let payload_hash = hex::encode(Sha256::digest(payload));
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k), uri_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{date}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{SECRET}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    vec![
        ("host".into(), host.into()),
        ("x-amz-date".into(), amz_date),
        ("x-amz-content-sha256".into(), payload_hash),
        ("authorization".into(), auth),
    ]
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub async fn signed_request(
    state: &AppState,
    method: Method,
    path: &str,
    query: BTreeMap<String, String>,
    body: Bytes,
    extra: &[(&str, &str)],
) -> (StatusCode, http::HeaderMap, Bytes) {
    let host = "127.0.0.1:9000";
    let qs = if query.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            query
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    let uri = format!("{path}{qs}");
    let headers = sign_headers(method.as_str(), path, &query, &body, host);
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::from(body)).unwrap();
    let app = router(state.clone());
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, headers, bytes)
}

pub async fn anon_request(
    state: &AppState,
    method: Method,
    path: &str,
) -> (StatusCode, Bytes) {
    let (status, _, body) = anon_request_with_headers(state, method, path, &[]).await;
    (status, body)
}

pub async fn anon_request_with_headers(
    state: &AppState,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, http::HeaderMap, Bytes) {
    let mut builder = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).unwrap();
    let app = router(state.clone());
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, resp_headers, bytes)
}

/// Options for building a SigV4 query-auth (presigned) request.
#[derive(Debug, Clone)]
pub struct PresignOpts<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub expires: u32,
    /// Extra query params included in the signature (e.g. `x-id=PutObject`).
    pub extra_query: &'a [(&'a str, &'a str)],
    /// Headers that are signed and must be sent with the request.
    /// Always includes `host`; add e.g. `content-type`.
    pub signed_headers: &'a [&'a str],
    /// Header values for signed headers (except host, which is fixed).
    pub header_values: &'a [(&'a str, &'a str)],
    /// Payload hash in the canonical request (`UNSIGNED-PAYLOAD` or hex SHA-256).
    pub payload_hash: &'a str,
    /// Optional override for `X-Amz-Date` / credential date (testing expiry).
    pub amz_date: Option<&'a str>,
    pub scope_date: Option<&'a str>,
    pub host: &'a str,
}

impl<'a> Default for PresignOpts<'a> {
    fn default() -> Self {
        Self {
            method: "PUT",
            path: "/",
            expires: 900,
            extra_query: &[("x-id", "PutObject")],
            signed_headers: &["host"],
            header_values: &[],
            payload_hash: "UNSIGNED-PAYLOAD",
            amz_date: None,
            scope_date: None,
            host: "127.0.0.1:9000",
        }
    }
}

/// Build a SigV4 query string for a presigned request (no leading `?`).
pub fn presign_query(opts: &PresignOpts<'_>) -> String {
    let now = Utc::now();
    let amz_date = opts
        .amz_date
        .map(str::to_string)
        .unwrap_or_else(|| now.format("%Y%m%dT%H%M%SZ").to_string());
    let date = opts
        .scope_date
        .map(str::to_string)
        .unwrap_or_else(|| now.format("%Y%m%d").to_string());
    let credential = format!("{ACCESS}/{date}/{REGION}/s3/aws4_request");

    let mut query: BTreeMap<String, String> = BTreeMap::new();
    query.insert("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into());
    query.insert("X-Amz-Credential".into(), credential);
    query.insert("X-Amz-Date".into(), amz_date.clone());
    query.insert("X-Amz-Expires".into(), opts.expires.to_string());
    let mut signed: Vec<String> = opts.signed_headers.iter().map(|s| s.to_ascii_lowercase()).collect();
    signed.sort();
    signed.dedup();
    query.insert("X-Amz-SignedHeaders".into(), signed.join(";"));
    if opts.payload_hash != "UNSIGNED-PAYLOAD" {
        query.insert("X-Amz-Content-Sha256".into(), opts.payload_hash.to_string());
    }
    for (k, v) in opts.extra_query {
        query.insert((*k).into(), (*v).into());
    }

    let mut parts = Vec::with_capacity(query.len());
    for (k, v) in &query {
        parts.push(format!("{}={}", uri_encode(k), uri_encode(v)));
    }
    let canonical_query = parts.join("&");

    let mut canonical_headers = String::new();
    for name in &signed {
        let value = if name == "host" {
            opts.host.to_string()
        } else {
            opts.header_values
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_default()
        };
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value.trim());
        canonical_headers.push('\n');
    }

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        opts.method,
        opts.path,
        canonical_query,
        canonical_headers,
        signed.join(";"),
        opts.payload_hash
    );
    let scope = format!("{date}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac_sha256(format!("AWS4{SECRET}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!("{canonical_query}&X-Amz-Signature={signature}")
}

/// Build a SigV4 query string for a presigned PUT (no leading `?`).
pub fn presigned_put_query(path: &str, expires: u32) -> String {
    presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires,
        ..PresignOpts::default()
    })
}

/// Perform an anonymous HTTP request authenticated only via a presigned query.
pub async fn presigned_request(
    state: &AppState,
    method: Method,
    path: &str,
    query: &str,
    body: Bytes,
    headers: &[(&str, &str)],
) -> (StatusCode, http::HeaderMap, Bytes) {
    let uri = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:9000");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::from(body)).unwrap();
    let app = router(state.clone());
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, resp_headers, bytes)
}

/// Build base64 POST policy JSON (SigV4) and sign it.
pub fn build_signed_post_fields_v4(
    bucket: &str,
    key: &str,
    content_type: Option<&str>,
    min_size: u64,
    max_size: u64,
    extra_conditions: Vec<serde_json::Value>,
) -> BTreeMap<String, String> {
    use base64::Engine;
    use chrono::Utc;

    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let expiration = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let credential = format!("{ACCESS}/{date}/{REGION}/s3/aws4_request");

    let mut conditions = vec![
        serde_json::json!({"bucket": bucket}),
        serde_json::json!({"key": key}),
        serde_json::json!({"x-amz-algorithm": "AWS4-HMAC-SHA256"}),
        serde_json::json!({"x-amz-credential": credential.clone()}),
        serde_json::json!({"x-amz-date": amz_date.clone()}),
        serde_json::json!(["content-length-range", min_size, max_size]),
    ];
    if let Some(ct) = content_type {
        conditions.push(serde_json::json!({"Content-Type": ct}));
    }
    conditions.extend(extra_conditions);

    let policy_doc = serde_json::json!({
        "expiration": expiration,
        "conditions": conditions,
    });
    let policy_json = serde_json::to_string(&policy_doc).unwrap();
    let policy_b64 = base64::engine::general_purpose::STANDARD.encode(policy_json.as_bytes());

    let k_date = hmac_sha256(format!("AWS4{SECRET}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, policy_b64.as_bytes()));

    let mut fields = BTreeMap::new();
    fields.insert("key".into(), key.into());
    fields.insert("policy".into(), policy_b64);
    fields.insert("x-amz-algorithm".into(), "AWS4-HMAC-SHA256".into());
    fields.insert("x-amz-credential".into(), credential);
    fields.insert("x-amz-date".into(), amz_date);
    fields.insert("x-amz-signature".into(), signature);
    if let Some(ct) = content_type {
        fields.insert("Content-Type".into(), ct.into());
    }
    fields
}

/// Perform a multipart POST object upload to `path` (e.g. `/uploads`).
pub async fn multipart_post_request(
    state: &AppState,
    path: &str,
    fields: &BTreeMap<String, String>,
    file_field: &str,
    file_name: &str,
    file_content_type: &str,
    file_body: &[u8],
) -> (StatusCode, http::HeaderMap, Bytes) {
    let boundary = "----FlashS3TestBoundary";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{file_field}\"; filename=\"{file_name}\"\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {file_content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(file_body);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("host", "127.0.0.1:9000")
        .body(Body::from(body))
        .unwrap();
    let app = router(state.clone());
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes)
}
