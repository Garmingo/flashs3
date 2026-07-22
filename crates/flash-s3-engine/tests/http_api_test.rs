//! End-to-end HTTP/S3 API tests (SigV4 + anonymous ACL).

mod common;

use std::collections::BTreeMap;

use bytes::Bytes;
use chrono::DateTime;
use flash_s3_engine::api::router;
use common::{anon_request, app_state, sign_headers, signed_request};
use axum::body::Body;
use http::{Method, Request, StatusCode};
use tower::ServiceExt;

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
async fn aws_chunked_put_stores_only_decoded_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/chunked",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;

    let wire = Bytes::from_static(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/chunked/object.bin",
        BTreeMap::new(),
        wire,
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "11"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, headers, body) = signed_request(
        &state,
        Method::GET,
        "/chunked/object.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"hello world"));
    assert_eq!(headers.get("content-encoding"), None);
    assert_eq!(headers.get("content-length").unwrap(), "11");
}

#[tokio::test]
async fn signed_payload_hash_mismatch_does_not_store_object() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/integrity",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;

    let headers = sign_headers(
        "PUT",
        "/integrity/hash.bin",
        &BTreeMap::new(),
        b"expected bytes",
        "127.0.0.1:9000",
    );
    let mut builder = Request::builder()
        .method(Method::PUT)
        .uri("/integrity/hash.bin");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let response = router(state.clone())
        .oneshot(builder.body(Body::from("different bytes")).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let (status, _, _) = signed_request(
        &state,
        Method::GET,
        "/integrity/hash.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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
async fn get_and_head_object_support_single_byte_ranges() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/ranges",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    let payload = Bytes::from_static(b"0123456789");
    signed_request(
        &state,
        Method::PUT,
        "/ranges/object.bin",
        BTreeMap::new(),
        payload.clone(),
        &[],
    )
    .await;

    // Force a cache miss: partial reads must stream only the requested bytes.
    state.cache.invalidate("ranges", "object.bin").await;
    let (status, headers, body) = signed_request(
        &state,
        Method::GET,
        "/ranges/object.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[("range", "bytes=2-5")],
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers.get("content-range").unwrap(), "bytes 2-5/10");
    assert_eq!(headers.get("content-length").unwrap(), "4");
    assert_eq!(body.as_ref(), b"2345");

    // Full GET fills the cache. A suffix range then slices cached bytes.
    let (status, _, body) = signed_request(
        &state,
        Method::GET,
        "/ranges/object.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);
    let (status, headers, body) = signed_request(
        &state,
        Method::GET,
        "/ranges/object.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[("range", "bytes=-3")],
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers.get("content-range").unwrap(), "bytes 7-9/10");
    assert_eq!(body.as_ref(), b"789");

    let (status, headers, body) = signed_request(
        &state,
        Method::HEAD,
        "/ranges/object.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[("range", "bytes=6-")],
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers.get("content-range").unwrap(), "bytes 6-9/10");
    assert_eq!(headers.get("content-length").unwrap(), "4");
    assert!(body.is_empty());
}

#[tokio::test]
async fn range_errors_return_expected_statuses() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    signed_request(
        &state,
        Method::PUT,
        "/range-errors",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    signed_request(
        &state,
        Method::PUT,
        "/range-errors/object.bin",
        BTreeMap::new(),
        Bytes::from_static(b"0123456789"),
        &[],
    )
    .await;

    for value in ["bytes=10-", "bytes=5-2", "bytes=-0", "items=0-1"] {
        let (status, headers, _) = signed_request(
            &state,
            Method::GET,
            "/range-errors/object.bin",
            BTreeMap::new(),
            Bytes::new(),
            &[("range", value)],
        )
        .await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE, "{value}");
        assert_eq!(headers.get("content-range").unwrap(), "bytes */10");
    }

    let (status, _, _) = signed_request(
        &state,
        Method::GET,
        "/range-errors/object.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[("range", "bytes=0-1,3-4")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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
