//! Integration tests for S3 parity features (listing, delete-multi, tagging,
//! virtual-host, location, checksums, SSE-S3, conditional put, multipart list/copy).

mod common;

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use common::{app_state, signed_request};
use crc::{Crc, CRC_32_ISO_HDLC};
use http::{Method, StatusCode};
use sha1::{Digest, Sha1};
use sha2::Sha256;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

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
    assert!(
        status == StatusCode::OK || status == StatusCode::CONFLICT,
        "{status}"
    );
}

async fn put_object(state: &flash_s3_engine::AppState, path: &str, body: &[u8]) {
    let (status, _, _) = signed_request(
        state,
        Method::PUT,
        path,
        BTreeMap::new(),
        Bytes::copy_from_slice(body),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "put {path}");
}

#[tokio::test]
async fn list_objects_v2_with_delimiter_common_prefixes() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "listme").await;
    put_object(&state, "/listme/photos/2024/a.jpg", b"a").await;
    put_object(&state, "/listme/photos/2024/b.jpg", b"b").await;
    put_object(&state, "/listme/photos/readme.txt", b"r").await;
    put_object(&state, "/listme/root.txt", b"x").await;

    let mut q = BTreeMap::new();
    q.insert("list-type".into(), "2".into());
    q.insert("delimiter".into(), "/".into());
    q.insert("prefix".into(), "photos/".into());
    let (status, _, body) =
        signed_request(&state, Method::GET, "/listme", q, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("<CommonPrefixes><Prefix>photos/2024/</Prefix>"));
    assert!(text.contains("<Key>photos/readme.txt</Key>"));
    assert!(!text.contains("<Key>photos/2024/a.jpg</Key>"));
}

#[tokio::test]
async fn list_objects_v1_uses_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "listv1").await;
    put_object(&state, "/listv1/a", b"1").await;
    put_object(&state, "/listv1/b", b"2").await;
    put_object(&state, "/listv1/c", b"3").await;

    let mut q = BTreeMap::new();
    q.insert("list-type".into(), "1".into());
    q.insert("marker".into(), "a".into());
    q.insert("max-keys".into(), "1".into());
    let (status, _, body) =
        signed_request(&state, Method::GET, "/listv1", q, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("<Key>b</Key>"));
    assert!(text.contains("<IsTruncated>true</IsTruncated>"));
    assert!(text.contains("<NextMarker>"));
}

#[tokio::test]
async fn get_bucket_location() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "locbucket").await;
    let mut q = BTreeMap::new();
    q.insert("location".into(), "".into());
    let (status, _, body) =
        signed_request(&state, Method::GET, "/locbucket", q, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("LocationConstraint"));
}

#[tokio::test]
async fn delete_objects_multi() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "delmulti").await;
    put_object(&state, "/delmulti/one", b"1").await;
    put_object(&state, "/delmulti/two", b"2").await;

    let xml = r#"<?xml version="1.0"?><Delete><Object><Key>one</Key></Object><Object><Key>missing</Key></Object><Object><Key>two</Key></Object></Delete>"#;
    let mut q = BTreeMap::new();
    q.insert("delete".into(), "".into());
    let (status, _, body) = signed_request(
        &state,
        Method::POST,
        "/delmulti",
        q,
        Bytes::from(xml),
        &[("content-type", "application/xml")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("<Deleted><Key>one</Key></Deleted>"));
    assert!(text.contains("<Deleted><Key>two</Key></Deleted>"));
    assert!(text.contains("<Deleted><Key>missing</Key></Deleted>") || text.contains("NoSuchKey"));
}

#[tokio::test]
async fn object_and_bucket_tagging_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "tagged").await;
    put_object(&state, "/tagged/obj", b"data").await;

    let tags = r#"<?xml version="1.0"?><Tagging><TagSet><Tag><Key>env</Key><Value>dev</Value></Tag></TagSet></Tagging>"#;
    let mut q = BTreeMap::new();
    q.insert("tagging".into(), "".into());
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/tagged/obj",
        q.clone(),
        Bytes::from(tags),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) =
        signed_request(&state, Method::GET, "/tagged/obj", q.clone(), Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("<Key>env</Key>"));

    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/tagged",
        q.clone(),
        Bytes::from(tags),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) =
        signed_request(&state, Method::GET, "/tagged", q, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("<Value>dev</Value>"));
}

#[tokio::test]
async fn virtual_hosted_style_put_get() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = common::test_config(tmp.path().to_path_buf());
    config.virtual_host_base = Some("s3.test".into());
    let state = flash_s3_engine::AppState::new(config).unwrap();
    ensure_bucket(&state, "vhbucket").await;

    // Path-style create already done; PUT via virtual host Host header.
    use flash_s3_engine::api::router;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let payload = b"vh-body";
    let payload_hash = hex::encode(Sha256::digest(payload));
    let host = "vhbucket.s3.test";
    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "PUT\n/obj\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    type HmacSha256 = hmac::Hmac<Sha256>;
    use hmac::Mac;
    let mut mac = HmacSha256::new_from_slice(format!("AWS4{}", common::SECRET).as_bytes()).unwrap();
    mac.update(date.as_bytes());
    let k_date = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&k_date).unwrap();
    mac.update(b"us-east-1");
    let k_region = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&k_region).unwrap();
    mac.update(b"s3");
    let k_service = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&k_service).unwrap();
    mac.update(b"aws4_request");
    let k_signing = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&k_signing).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        common::ACCESS
    );

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/obj")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &payload_hash)
        .header("authorization", auth)
        .body(Body::from(payload.as_slice()))
        .unwrap();
    let resp = router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        "/vhbucket/obj",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got.as_ref(), payload);
}

#[tokio::test]
async fn checksum_crc32_and_sha1_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "chksum").await;
    let body = b"checksum-body";
    let crc = B64.encode(CRC32.checksum(body).to_be_bytes());
    let sha1 = B64.encode(Sha1::digest(body));

    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/chksum/ok.bin",
        BTreeMap::new(),
        Bytes::from_static(body),
        &[
            ("x-amz-checksum-crc32", crc.as_str()),
            ("x-amz-checksum-sha1", sha1.as_str()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, resp) = signed_request(
        &state,
        Method::PUT,
        "/chksum/bad.bin",
        BTreeMap::new(),
        Bytes::from_static(body),
        &[("x-amz-checksum-crc32", "AAAAAA==")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&resp).contains("BadDigest"));
}

#[tokio::test]
async fn conditional_put_if_none_match_star() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "condput").await;

    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/condput/only-once",
        BTreeMap::new(),
        Bytes::from_static(b"first"),
        &[("if-none-match", "*")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = signed_request(
        &state,
        Method::PUT,
        "/condput/only-once",
        BTreeMap::new(),
        Bytes::from_static(b"second"),
        &[("if-none-match", "*")],
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(String::from_utf8_lossy(&body).contains("PreconditionFailed"));
}

#[tokio::test]
async fn sse_s3_put_get_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = common::test_config(tmp.path().to_path_buf());
    config.sse_s3_key = Some("test-sse-passphrase".into());
    let state = flash_s3_engine::AppState::new(config).unwrap();
    ensure_bucket(&state, "ssebuck").await;

    let payload = b"secret-plaintext";
    let (status, headers, _) = signed_request(
        &state,
        Method::PUT,
        "/ssebuck/secret.bin",
        BTreeMap::new(),
        Bytes::from_static(payload),
        &[("x-amz-server-side-encryption", "AES256")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );

    let (status, headers, got) = signed_request(
        &state,
        Method::GET,
        "/ssebuck/secret.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got.as_ref(), payload);
    assert_eq!(
        headers
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );

    // On-disk body must not equal plaintext.
    let data_path = flash_s3_engine::storage::layout::data_path(
        tmp.path(),
        "ssebuck",
        "secret.bin",
    );
    let disk = std::fs::read(&data_path).unwrap();
    assert_ne!(disk.as_slice(), payload);
}

#[tokio::test]
async fn copy_object_metadata_directive_replace() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "copymeta").await;
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/copymeta/src",
        BTreeMap::new(),
        Bytes::from_static(b"body"),
        &[("x-amz-meta-color", "blue")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/copymeta/dst",
        BTreeMap::new(),
        Bytes::new(),
        &[
            ("x-amz-copy-source", "/copymeta/src"),
            ("x-amz-metadata-directive", "REPLACE"),
            ("x-amz-meta-color", "red"),
            ("content-type", "text/plain"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, headers, _) = signed_request(
        &state,
        Method::HEAD,
        "/copymeta/dst",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("x-amz-meta-color")
            .and_then(|v| v.to_str().ok()),
        Some("red")
    );
}

#[tokio::test]
async fn list_multipart_uploads_and_upload_part_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "mpu").await;
    put_object(&state, "/mpu/source.bin", b"ABCDEFGHIJ").await;

    let mut q = BTreeMap::new();
    q.insert("uploads".into(), "".into());
    let (status, _, body) =
        signed_request(&state, Method::POST, "/mpu/dest.bin", q, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    let upload_id = text
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    let mut list_q = BTreeMap::new();
    list_q.insert("uploads".into(), "".into());
    let (status, _, body) =
        signed_request(&state, Method::GET, "/mpu", list_q, Bytes::new(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains(&upload_id));

    let mut part_q = BTreeMap::new();
    part_q.insert("partNumber".into(), "1".into());
    part_q.insert("uploadId".into(), upload_id.clone());
    let (status, _, body) = signed_request(
        &state,
        Method::PUT,
        "/mpu/dest.bin",
        part_q,
        Bytes::new(),
        &[("x-amz-copy-source", "/mpu/source.bin")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "upload part copy: {}",
        String::from_utf8_lossy(&body)
    );
    let text = String::from_utf8_lossy(&body);
    let etag1 = text
        .split("<ETag>")
        .nth(1)
        .unwrap()
        .split("</ETag>")
        .next()
        .unwrap()
        .to_string();

    let complete = format!(
        r#"<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part></CompleteMultipartUpload>"#
    );
    let mut cq = BTreeMap::new();
    cq.insert("uploadId".into(), upload_id);
    let (status, _, body) = signed_request(
        &state,
        Method::POST,
        "/mpu/dest.bin",
        cq,
        Bytes::from(complete),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "complete: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, _, got) = signed_request(
        &state,
        Method::GET,
        "/mpu/dest.bin",
        BTreeMap::new(),
        Bytes::new(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got.as_ref(), b"ABCDEFGHIJ");
}

#[tokio::test]
async fn policy_condition_string_like_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let state = app_state(&tmp);
    ensure_bucket(&state, "polcond").await;

    let policy = r#"{
      "Version":"2012-10-17",
      "Statement":[{
        "Effect":"Allow",
        "Principal":"*",
        "Action":"s3:ListBucket",
        "Resource":"arn:aws:s3:::polcond",
        "Condition":{"StringLike":{"s3:prefix":["public/*"]}}
      },{
        "Effect":"Deny",
        "Principal":"*",
        "Action":"s3:ListBucket",
        "Resource":"arn:aws:s3:::polcond",
        "Condition":{"StringLike":{"s3:prefix":["secret/*"]}}
      }]
    }"#;
    let mut q = BTreeMap::new();
    q.insert("policy".into(), "".into());
    let (status, _, _) = signed_request(
        &state,
        Method::PUT,
        "/polcond",
        q,
        Bytes::from(policy),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Root bypasses ACL/policy by default — use a listing that still works via root.
    // Instead verify condition evaluation unit-style via load_policy.
    let pol = state.store.load_policy("polcond").await.unwrap().unwrap();
    let ctx_ok = flash_s3_common::PolicyConditionCtx {
        access_key: Some("flash"),
        s3_prefix: Some("public/a"),
        s3_delimiter: None,
        s3_x_amz_acl: None,
    };
    assert_eq!(
        pol.evaluate(
            "s3:ListBucket",
            "arn:aws:s3:::polcond",
            Some("flash"),
            Some(&ctx_ok)
        ),
        Some(true)
    );
    let ctx_deny = flash_s3_common::PolicyConditionCtx {
        access_key: Some("flash"),
        s3_prefix: Some("secret/a"),
        s3_delimiter: None,
        s3_x_amz_acl: None,
    };
    assert_eq!(
        pol.evaluate(
            "s3:ListBucket",
            "arn:aws:s3:::polcond",
            Some("flash"),
            Some(&ctx_deny)
        ),
        Some(false)
    );
}
