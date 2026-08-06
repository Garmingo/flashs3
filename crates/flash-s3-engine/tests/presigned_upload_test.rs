//! HTTP integration tests for S3 SigV4 query-string (presigned URL) uploads.
//!
//! Covers the official query-auth contract from
//! https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

mod common;

use std::collections::BTreeMap;

use bytes::Bytes;
use common::{
    app_state, presign_query, presigned_put_query, presigned_request, signed_request, PresignOpts,
};
use http::{Method, StatusCode};
use sha2::{Digest, Sha256};

async fn ensure_bucket(state: &flash_s3_engine::AppState, name: &str) {
    let (status, _, _) = signed_request(
        state,
        Method::PUT,
        &format!("/{name}"),
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_unsigned_payload_uploads_and_is_readable() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/uploads/file.bin";
    let body = Bytes::from_static(b"presigned-body-bytes");
    let qs = presigned_put_query(path, 900);
    let (status, headers, _) =
        presigned_request(&state, Method::PUT, path, &qs, body.clone(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("etag").is_some());

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        path,
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, body);
}

#[tokio::test]
async fn presigned_put_with_encoded_object_key() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    // Path used for signing must be the URI-encoded form (SigV4 / S3).
    let path = "/presign/pending/update%20one.zip";
    let body = Bytes::from_static(b"zip");
    let qs = presigned_put_query(path, 600);
    let (status, _, _) =
        presigned_request(&state, Method::PUT, path, &qs, body.clone(), &[]).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        "/presign/pending/update%20one.zip",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, body);
}

#[tokio::test]
async fn presigned_put_requires_signed_content_type_when_included() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/typed.bin";
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 900,
        signed_headers: &["content-type", "host"],
        header_values: &[("content-type", "application/zip")],
        ..PresignOpts::default()
    });

    // Missing content-type → signature verification fails (signed header absent).
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));

    // Wrong content-type → fail.
    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"x"),
        &[("content-type", "text/plain")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Matching content-type → ok.
    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"x"),
        &[("content-type", "application/zip")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_with_content_sha256_enforces_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/hashed.bin";
    let expected = b"exact-payload";
    let hash = hex::encode(Sha256::digest(expected));
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 900,
        payload_hash: &hash,
        ..PresignOpts::default()
    });

    let (status, _, body) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"wrong-payload"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("XAmzContentSHA256Mismatch"));

    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::copy_from_slice(expected),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_rejects_tampered_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/tamper.bin";
    let qs = presigned_put_query(path, 900);
    let idx = qs.find("X-Amz-Signature=").expect("signature param");
    let qs = format!("{}X-Amz-Signature={}", &qs[..idx], "ab".repeat(32));
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn presigned_put_rejects_query_param_added_after_signing() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/extra.bin";
    let qs = format!("{}&hacker=1", presigned_put_query(path, 900));
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn presigned_put_rejects_method_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/method.bin";
    // Sign as PUT, call as GET.
    let qs = presigned_put_query(path, 900);
    let (status, _, body) =
        presigned_request(&state, Method::GET, path, &qs, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn presigned_put_rejects_expired_url() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/expired.bin";
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 1,
        amz_date: Some("20200101T000000Z"),
        scope_date: Some("20200101"),
        ..PresignOpts::default()
    });
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("AccessDenied"));
}

#[tokio::test]
async fn presigned_put_rejects_expires_out_of_range() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/bad-expires.bin";
    // expires=0 is invalid per S3 (min 1, max 604800).
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 0,
        ..PresignOpts::default()
    });
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("AccessDenied"));
}

#[tokio::test]
async fn presigned_put_accepts_max_expires_seven_days() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/week.bin";
    let qs = presigned_put_query(path, 604_800);
    let (status, _, _) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"ok"), &[]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_rejects_wrong_algorithm() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/algo.bin";
    let qs = presigned_put_query(path, 900).replace(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256",
        "X-Amz-Algorithm=AWS4-HMAC-SHA1",
    );
    // Signature no longer matches either, but algorithm check should fail first-ish.
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("SignatureDoesNotMatch") || text.contains("AccessDenied"),
        "{text}"
    );
}

#[tokio::test]
async fn presigned_put_rejects_unknown_access_key() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/badkey.bin";
    // Credential is URI-encoded in the query (`flash%2F…`).
    let qs = presigned_put_query(path, 900).replace("flash%2F", "NOPE%2F");
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("InvalidAccessKeyId"));
}

#[tokio::test]
async fn presigned_put_then_cors_preflight_still_works() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = common::test_config(tmp.path().to_path_buf());
    config.default_bucket_name = Some("pscors".into());
    config.default_bucket_cors_allow_all = true;
    let state = flash_s3_engine::AppState::new(config).unwrap();
    state.initialize_default_bucket().await.unwrap();

    let path = "/pscors/web/upload.bin";
    let qs = presigned_put_query(path, 1800);
    let (status, headers, _) = common::anon_request_with_headers(
        &state,
        Method::OPTIONS,
        &format!("{path}?{qs}"),
        &[
            ("Origin", "http://localhost:3001"),
            ("Access-Control-Request-Method", "PUT"),
            ("Access-Control-Request-Headers", "content-type"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");

    let (status, headers, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"from-browser"),
        &[
            ("content-type", "application/octet-stream"),
            ("Origin", "http://localhost:3001"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
}

#[tokio::test]
async fn presigned_get_downloads_object() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/download.bin";
    let body = Bytes::from_static(b"download-me");
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        path,
        BTreeMap::new(),
        body.clone(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let qs = presign_query(&PresignOpts {
        method: "GET",
        path,
        expires: 900,
        extra_query: &[],
        ..PresignOpts::default()
    });
    let (status, _, got) =
        presigned_request(&state, Method::GET, path, &qs, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, body);
}

#[tokio::test]
async fn presigned_put_accepts_min_expires_one_second() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/min-expires.bin";
    let qs = presigned_put_query(path, 1);
    let (status, _, _) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"ok"), &[]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_rejects_expires_above_seven_days() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/too-long.bin";
    // Spec: max X-Amz-Expires is 604800 (7 days).
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 604_801,
        ..PresignOpts::default()
    });
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("AccessDenied"));
}

#[tokio::test]
async fn presigned_put_rejects_host_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/host.bin";
    // Signed for a different host than the request Host header.
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 900,
        host: "evil.example:9000",
        ..PresignOpts::default()
    });
    let (status, _, body) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::from_static(b"x"), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn presigned_put_rejects_path_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let signed_path = "/presign/legit.bin";
    let qs = presigned_put_query(signed_path, 900);
    let (status, _, body) = presigned_request(
        &state,
        Method::PUT,
        "/presign/other.bin",
        &qs,
        Bytes::from_static(b"x"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn presigned_put_rejects_missing_required_query_params() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/missing.bin";
    let full = presigned_put_query(path, 900);

    // Drop X-Amz-Credential (URI-encoded value follows).
    let without_cred: String = full
        .split('&')
        .filter(|p| !p.starts_with("X-Amz-Credential="))
        .collect::<Vec<_>>()
        .join("&");
    let (status, _, body) = presigned_request(
        &state,
        Method::PUT,
        path,
        &without_cred,
        Bytes::from_static(b"x"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));

    let without_date: String = full
        .split('&')
        .filter(|p| !p.starts_with("X-Amz-Date="))
        .collect::<Vec<_>>()
        .join("&");
    let (status, _, body) = presigned_request(
        &state,
        Method::PUT,
        path,
        &without_date,
        Bytes::from_static(b"x"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn presigned_put_empty_body_unsigned_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/empty.bin";
    let qs = presigned_put_query(path, 900);
    let (status, _, _) =
        presigned_request(&state, Method::PUT, path, &qs, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        path,
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(got.is_empty());
}

#[tokio::test]
async fn presigned_put_allows_unsigned_content_type_header() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    // Only `host` is signed; browsers may still send Content-Type.
    let path = "/presign/unsigned-ct.bin";
    let qs = presigned_put_query(path, 900);
    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"payload"),
        &[("content-type", "application/octet-stream")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_requires_signed_user_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/meta.bin";
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 900,
        signed_headers: &["host", "x-amz-meta-filename"],
        header_values: &[("x-amz-meta-filename", "report.zip")],
        ..PresignOpts::default()
    });

    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"x"),
        &[("x-amz-meta-filename", "other.zip")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &qs,
        Bytes::from_static(b"x"),
        &[("x-amz-meta-filename", "report.zip")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn presigned_put_with_nested_key_and_sdk_style_xid() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/a/b/c/nested.bin";
    let qs = presign_query(&PresignOpts {
        method: "PUT",
        path,
        expires: 900,
        extra_query: &[("x-id", "PutObject")],
        ..PresignOpts::default()
    });
    let body = Bytes::from_static(b"nested");
    let (status, _, _) =
        presigned_request(&state, Method::PUT, path, &qs, body.clone(), &[]).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        path,
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, body);
}

#[tokio::test]
async fn presigned_put_query_param_order_does_not_matter() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "presign").await;

    let path = "/presign/reorder.bin";
    let qs = presigned_put_query(path, 900);
    // Reverse parameter order; canonicalization must sort before verify.
    let reordered = qs.split('&').rev().collect::<Vec<_>>().join("&");
    assert_ne!(qs, reordered);
    let (status, _, _) = presigned_request(
        &state,
        Method::PUT,
        path,
        &reordered,
        Bytes::from_static(b"ok"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
