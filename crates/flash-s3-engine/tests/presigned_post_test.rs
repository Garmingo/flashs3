//! HTTP integration tests for S3 POST object (presigned POST / browser upload).

mod common;

use bytes::Bytes;
use common::{
    app_state, build_signed_post_fields_v4, multipart_post_request, signed_request,
    ACCESS, REGION, SECRET,
};
use http::{Method, StatusCode};
use std::collections::BTreeMap;

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
async fn presigned_post_uploads_object() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "uploads").await;

    let key = "87f4a3d6-4b4d-45ca-8fd5-fd05d8bc73a8/plane-image.jpg";
    let body = vec![0xabu8; 64 * 1024];
    let fields = build_signed_post_fields_v4("uploads", key, Some("image/jpeg"), 1, 200_000, vec![]);

    let (status, _, resp_body) =
        multipart_post_request(&state, "/uploads", &fields, "file", "plane.jpg", "image/jpeg", &body)
            .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&resp_body)
    );

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        &format!("/uploads/{key}"),
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got.as_ref(), body);
}

#[tokio::test]
async fn presigned_post_rejects_bad_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "uploads").await;

    let mut fields = build_signed_post_fields_v4("uploads", "bad.jpg", Some("image/jpeg"), 1, 1000, vec![]);
    fields.insert("x-amz-signature".into(), "deadbeef".repeat(8));

    let (status, _, _) =
        multipart_post_request(&state, "/uploads", &fields, "file", "x.jpg", "image/jpeg", b"x").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn presigned_post_rejects_expired_policy() {
    use base64::Engine;
    use chrono::Utc;

    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "uploads").await;

    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let expiration = (now - chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let credential = format!("{ACCESS}/{date}/{REGION}/s3/aws4_request");
    let policy_doc = serde_json::json!({
        "expiration": expiration,
        "conditions": [
            {"bucket": "uploads"},
            {"key": "k"},
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
            {"x-amz-credential": credential},
            {"x-amz-date": amz_date},
            ["content-length-range", 1, 1000],
        ]
    });
    let policy_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_string(&policy_doc).unwrap().as_bytes());
    let k_date = common::hmac_sha256(format!("AWS4{SECRET}").as_bytes(), date.as_bytes());
    let k_region = common::hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = common::hmac_sha256(&k_region, b"s3");
    let k_signing = common::hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(common::hmac_sha256(&k_signing, policy_b64.as_bytes()));

    let mut fields = BTreeMap::new();
    fields.insert("key".into(), "k".into());
    fields.insert("policy".into(), policy_b64);
    fields.insert("x-amz-algorithm".into(), "AWS4-HMAC-SHA256".into());
    fields.insert("x-amz-credential".into(), credential);
    fields.insert("x-amz-date".into(), amz_date);
    fields.insert("x-amz-signature".into(), signature);

    let (status, _, _) =
        multipart_post_request(&state, "/uploads", &fields, "file", "x.jpg", "image/jpeg", b"x").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn presigned_post_enforces_content_length_range() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "uploads").await;

    let fields = build_signed_post_fields_v4("uploads", "big.bin", None, 1, 4, vec![]);
    let (status, _, _) =
        multipart_post_request(&state, "/uploads", &fields, "file", "big.bin", "application/octet-stream", &[0u8; 8])
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn presigned_post_success_action_status_201() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "uploads").await;

    let mut fields = build_signed_post_fields_v4("uploads", "ok.txt", Some("text/plain"), 1, 1000, vec![]);
    fields.insert("success_action_status".into(), "201".into());

    let (status, _, body) =
        multipart_post_request(&state, "/uploads", &fields, "file", "ok.txt", "text/plain", b"hello").await;
    assert_eq!(status, StatusCode::CREATED);
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>ok.txt</Key>"));
    assert!(xml.contains("<ETag>"));
}
