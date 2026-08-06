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

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
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
