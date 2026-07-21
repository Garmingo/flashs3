//! End-to-end HTTP/S3 API tests (SigV4 + anonymous ACL).

mod common;

use std::collections::BTreeMap;

use bytes::Bytes;
use chrono::DateTime;
use common::{anon_request, app_state, signed_request};
use http::{Method, StatusCode};

#[tokio::test]
async fn health_and_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    let (status, body) = anon_request(&state, Method::GET, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ok");
    let (status, body) = anon_request(&state, Method::GET, "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ready");
}

#[tokio::test]
async fn configured_default_bucket_is_created_idempotently() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = common::test_config(tmp.path().to_path_buf());
    config.default_bucket_name = Some("bootstrap".into());
    let state = flash_s3_engine::AppState::new(config).unwrap();

    state.initialize_default_bucket().await.unwrap();
    state.initialize_default_bucket().await.unwrap();

    let bucket = state.store.get_bucket("bootstrap").await.unwrap();
    assert_eq!(bucket.name, "bootstrap");
}

#[tokio::test]
async fn bucket_object_crud_via_http() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);

    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/demo",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let payload = Bytes::from_static(b"http-hello");
    let (status, headers, _) = signed_request(
        &state,
        Method::PUT,
        "/demo/hello.txt",
        BTreeMap::new(),
        payload.clone(),
        &[("content-type", "text/plain")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("etag").is_some());

    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/demo/hello.txt",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);

    let (status, headers, _) = signed_request(
        &state,
        Method::HEAD,
        "/demo/hello.txt",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let last_modified = headers
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        DateTime::parse_from_rfc2822(last_modified).is_ok(),
        "Last-Modified must be an RFC 7231 HTTP-date: {last_modified}"
    );

    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/demo",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>hello.txt</Key>"));
}

#[tokio::test]
async fn public_read_acl_allows_anonymous_get() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);

    signed_request(
        &state,
        Method::PUT,
        "/pub",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    signed_request(
        &state,
        Method::PUT,
        "/pub/file.bin",
        BTreeMap::new(),
        Bytes::from_static(b"cdn-bytes"),
        &[],
    )
    .await;

    // private by default → anon denied
    let (status, _) = anon_request(&state, Method::GET, "/pub/file.bin").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let mut q = BTreeMap::new();
    q.insert("acl".into(), String::new());
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/pub/file.bin",
        q,
        Bytes::new(),
        &[("x-amz-acl", "public-read")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = anon_request(&state, Method::GET, "/pub/file.bin").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"cdn-bytes");
}

#[tokio::test]
async fn cache_hit_after_second_get() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);

    signed_request(
        &state,
        Method::PUT,
        "/cache",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    let payload = Bytes::from(vec![7u8; 1024]);
    signed_request(
        &state,
        Method::PUT,
        "/cache/hot.bin",
        BTreeMap::new(),
        payload.clone(),
        &[],
    )
    .await;

    // Put already inserts small objects into the cache; GET should hit.
    let hits_before = state.metrics.cache_hits.get();
    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/cache/hot.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);
    assert!(
        state.metrics.cache_hits.get() > hits_before,
        "expected cache hit after put populated the cache"
    );

    // Invalidate and read again → miss then re-fill
    state.cache.invalidate("cache", "hot.bin").await;
    let misses_before = state.metrics.cache_misses.get();
    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/cache/hot.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);
    assert!(state.metrics.cache_misses.get() > misses_before);
}

#[tokio::test]
async fn bucket_policy_get() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/pol",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;

    let policy = br#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"}]}"#;
    let mut q = BTreeMap::new();
    q.insert("policy".into(), String::new());
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/pol",
        q.clone(),
        Bytes::from_static(policy),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/pol",
        q,
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.windows(policy.len()).any(|w| w == policy));
}

#[tokio::test]
async fn copy_object_http() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/cpy",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    signed_request(
        &state,
        Method::PUT,
        "/cpy/src.txt",
        BTreeMap::new(),
        Bytes::from_static(b"to-copy"),
        &[],
    )
    .await;

    let (status, _, body) = signed_request(
        &state,
        Method::PUT,
        "/cpy/dst.txt",
        BTreeMap::new(),
        Bytes::new(),
        &[("x-amz-copy-source", "/cpy/src.txt")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("CopyObjectResult"));

    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/cpy/dst.txt",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"to-copy");
}

#[tokio::test]
async fn multipart_http() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/mpu",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;

    let mut q = BTreeMap::new();
    q.insert("uploads".into(), String::new());
    let (status, _, body) = signed_request(
        &state,
        Method::POST,
        "/mpu/large.bin",
        q,
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let xml = String::from_utf8_lossy(&body);
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let part = Bytes::from(vec![9u8; 512]);
    let mut q = BTreeMap::new();
    q.insert("partNumber".into(), "1".into());
    q.insert("uploadId".into(), upload_id.clone());
    let (status, headers, _) = signed_request(
        &state,
        Method::PUT,
        "/mpu/large.bin",
        q,
        part.clone(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let etag = headers
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let complete = format!(
        r#"<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"#
    );
    let mut q = BTreeMap::new();
    q.insert("uploadId".into(), upload_id);
    let (status, _, _) = signed_request(
        &state,
        Method::POST,
        "/mpu/large.bin",
        q,
        Bytes::from(complete),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/mpu/large.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, part);
}

#[tokio::test]
async fn metrics_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    let (status, body) = anon_request(&state, Method::GET, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("flashs3_cache_hits_total"));
    assert!(text.contains("flashs3_s3_requests_total") || text.contains("flashs3_cache_bytes"));
}
