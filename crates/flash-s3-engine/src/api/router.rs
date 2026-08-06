//! Path-style S3 request router and handlers.
//!
//! A single catch-all dispatches on HTTP method + query flags (`acl`, `policy`,
//! `cors`, `uploads`, `uploadId`, …) to keep Axum routing simple while covering the
//! S3 API surface we implement.

use std::collections::BTreeMap;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use chrono::DateTime;
use flash_s3_common::{
    allowed_request_headers, AccessControlPolicy, CannedAcl, CorsConfiguration, CorsRule,
    FlashError, ObjectKey, Permission, PolicyConditionCtx,
};
use futures::{StreamExt, TryStreamExt};
use md5::Digest as Md5Digest;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::{ReaderStream, StreamReader};
use tower_http::catch_panic::CatchPanicLayer;
use uuid::Uuid;

use crate::api::error::{s3_error_response, xml_escape, ApiError};
use crate::api::aws_chunked::{AwsChunkedConfig, AwsChunkedReader, PayloadHashReader};
use crate::api::xml;
use crate::auth::{hash_payload, verify_request, AuthContext, S3Action};
use crate::server::AppState;
use crate::storage::{PutObjectOpts, verify_checksums, request_wants_sse_s3, sse_encrypt};

/// Build the Axum router with health/metrics and the S3 catch-all.
///
/// Includes [`CatchPanicLayer`] so a handler panic becomes HTTP 500 instead of
/// killing the process.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/", any(root_handler))
        .route("/{*path}", any(path_handler))
        .layer(CatchPanicLayer::custom(|_err: Box<dyn std::any::Any + Send>| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/xml")],
                r#"<?xml version="1.0"?><Error><Code>InternalError</Code><Message>panic</Message></Error>"#,
            )
                .into_response()
        }))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.store.is_ready() {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}

async fn metrics(State(state): State<AppState>) -> Response {
    match state.metrics.gather() {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            body,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string(),
        )
            .into_response(),
    }
}

async fn root_handler(State(state): State<AppState>, req: Request) -> Response {
    dispatch(state, req, None).await
}

async fn path_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request,
) -> Response {
    dispatch(state, req, Some(path)).await
}

async fn dispatch(state: AppState, req: Request, path: Option<String>) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let resource = path.clone().unwrap_or_else(|| "/".into());
    let bucket_for_cors = path.as_deref().and_then(|p| {
        p.split('/')
            .find(|segment| !segment.is_empty())
            .map(str::to_string)
    });
    let result =
        dispatch_inner(state.clone(), method.clone(), uri, headers.clone(), req.into_body(), path, &request_id).await;
    let mut resp = match result {
        Ok(resp) => resp,
        Err(err) => s3_error_response(err, &resource, &request_id),
    };

    // OPTIONS responses already carry CORS headers from the preflight handler.
    if method != Method::OPTIONS {
        if let (Some(bucket), Some(origin)) = (
            bucket_for_cors.as_deref(),
            headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
        ) {
            maybe_apply_cors_headers(&state, bucket, method.as_str(), origin, &mut resp).await;
        }
    }
    resp
}

async fn dispatch_inner(
    state: AppState,
    method: Method,
    uri: http::Uri,
    headers: HeaderMap,
    body: Body,
    path: Option<String>,
    request_id: &str,
) -> Result<Response, FlashError> {
    let raw_query = uri.query().unwrap_or("");
    let query_map = parse_query(raw_query);
    // SigV4 signs the percent-encoded request path. `Path<String>` is decoded
    // by Axum, so retain the raw URI path for signature verification.
    let path_str = uri.path().to_string();

    // Browser CORS preflight for a presigned PUT/GET hits the same URL including
    // `X-Amz-Signature` query params. Auth must be skipped: the signature was
    // computed for the actual method (e.g. PUT), not OPTIONS. AWS S3 likewise
    // evaluates only the bucket CORS config for OPTIONS.
    if method == Method::OPTIONS {
        let path = path.ok_or_else(|| FlashError::InvalidRequest("missing path".into()))?;
        let bucket = path
            .split('/')
            .find(|segment| !segment.is_empty())
            .ok_or_else(|| FlashError::InvalidRequest("empty path".into()))?;
        drop(body);
        return handle_options_cors(&state, bucket, &headers, request_id).await;
    }

    let has_object_key = path
        .as_deref()
        .map(|p| p.split('/').filter(|segment| !segment.is_empty()).count() > 1)
        .unwrap_or(false);
    // Stream PutObject / UploadPart. Presigned PutObject carries `X-Amz-*` query
    // params, so "empty query" is not a valid PutObject signal — treat SigV4-only
    // query maps as PutObject too. Otherwise large uploads hit the 16 MiB control
    // buffer and fail with "buffered operation limit".
    let is_streaming_upload = method == Method::PUT
        && has_object_key
        && !headers.contains_key("x-amz-copy-source")
        && !query_map.contains_key("acl")
        && !query_map.contains_key("tagging")
        && (query_map.contains_key("partNumber") || query_allows_streaming_put(&query_map));
    let aws_chunked = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("aws-chunked"))
        });
    if is_streaming_upload
        && (headers.contains_key("x-amz-content-sha256")
            || query_map.contains_key("X-Amz-Signature")
            || aws_chunked)
    {
        let payload_hash = headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .or_else(|| query_map.get("X-Amz-Content-Sha256").map(String::as_str))
            .unwrap_or("UNSIGNED-PAYLOAD");
        let ctx = authenticate(
            &state,
            &method,
            &path_str,
            &query_map,
            raw_query,
            &headers,
            payload_hash,
        )?;
        let (bucket_opt, key_opt) = resolve_bucket_key(&state, &headers, path.as_deref());
        let bucket = bucket_opt.ok_or_else(|| FlashError::InvalidRequest("missing bucket".into()))?;
        let key_raw = key_opt.ok_or_else(|| FlashError::InvalidRequest("missing object key".into()))?;
        let key = ObjectKey::new(&key_raw).map_err(|_| FlashError::InvalidObjectName)?;
        let stream = TryStreamExt::map_err(body.into_data_stream(), std::io::Error::other);
        let raw_reader = StreamReader::new(stream);
        let reader: Box<dyn AsyncRead + Send + Unpin> = if aws_chunked {
            let decoded_length = headers
                .get("x-amz-decoded-content-length")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| FlashError::InvalidRequest("missing x-amz-decoded-content-length".into()))?
                .parse()
                .map_err(|_| FlashError::InvalidRequest("invalid x-amz-decoded-content-length".into()))?;
            Box::new(AwsChunkedReader::new(
                raw_reader,
                AwsChunkedConfig {
                    decoded_length: Some(decoded_length),
                    require_chunk_signatures: payload_hash
                        .starts_with("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
                    signing: ctx.streaming.clone(),
                    required_trailers: headers
                        .get("x-amz-trailer")
                        .and_then(|value| value.to_str().ok())
                        .map(|value| {
                            value
                                .split(',')
                                .map(|name| name.trim().to_ascii_lowercase())
                                .filter(|name| !name.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    expected_sha256_checksum: headers
                        .get("x-amz-checksum-sha256")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                },
            ))
        } else {
            let is_literal_hash = payload_hash.len() == 64
                && payload_hash.bytes().all(|byte| byte.is_ascii_hexdigit());
            if is_literal_hash {
                Box::new(PayloadHashReader::new(raw_reader, payload_hash.to_string()))
            } else {
                Box::new(raw_reader)
            }
        };
        return object_ops_stream(
            &state,
            &ctx,
            &bucket,
            &key,
            &query_map,
            &headers,
            reader,
            request_id,
        )
        .await;
    }

    let body_bytes = collect_control_body(body).await?;

    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if body_bytes.is_empty() {
                hash_payload(b"")
            } else {
                hash_payload(&body_bytes)
            }
        });

    let ctx = authenticate(
        &state,
        &method,
        &path_str,
        &query_map,
        raw_query,
        &headers,
        &payload_hash,
    )?;
    validate_buffered_integrity(&headers, &body_bytes)?;
    // Query-string auth may bind a concrete payload hash (`X-Amz-Content-Sha256`).
    // S3 verifies the body against that value when it is not UNSIGNED-PAYLOAD.
    if let Some(expected) = query_map.get("X-Amz-Content-Sha256") {
        if expected != "UNSIGNED-PAYLOAD" && expected.as_str() != hash_payload(&body_bytes) {
            return Err(FlashError::ContentSha256Mismatch);
        }
    }

    // Virtual-hosted-style bucket extraction
    let (bucket, key_raw) = resolve_bucket_key(&state, &headers, path.as_deref());

    if bucket.is_none() && method == Method::GET {
        return list_buckets(&state, &ctx, request_id).await;
    }

    let bucket = bucket.ok_or_else(|| FlashError::InvalidRequest("missing bucket".into()))?;

    // Bucket-level
    if key_raw.is_none() {
        return bucket_ops(&state, &ctx, &method, &bucket, &query_map, &headers, &body_bytes, request_id)
            .await;
    }

    let key = ObjectKey::new(key_raw.as_ref().unwrap())
        .map_err(|_| FlashError::InvalidObjectName)?;
    object_ops(
        &state,
        &ctx,
        &method,
        &bucket,
        &key,
        &query_map,
        &headers,
        body_bytes,
        request_id,
    )
    .await
}

/// Resolve bucket and key from either virtual-hosted-style or path-style.
fn resolve_bucket_key(
    state: &AppState,
    headers: &HeaderMap,
    path: Option<&str>,
) -> (Option<String>, Option<String>) {
    if let Some(base) = state.config.virtual_host_base.as_deref() {
        if let Some(host_val) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
            let host = host_val.split(':').next().unwrap_or(host_val);
            if let Some(bucket) = host.strip_suffix(&format!(".{}", base)) {
                if !bucket.is_empty() {
                    let key_raw = path.and_then(object_key_from_path_tail);
                    return (Some(bucket.to_string()), key_raw);
                }
            }
        }
    }
    // Path-style fallback
    match path {
        Some(p) => {
            let mut segments: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
            if segments.is_empty() {
                (None, None)
            } else {
                let bucket = segments.remove(0).to_string();
                let key = if segments.is_empty() {
                    None
                } else {
                    // Preserve trailing slash (`foo/` is a distinct S3 object key).
                    let mut key = segments.join("/");
                    if p.ends_with('/') {
                        key.push('/');
                    }
                    Some(key)
                };
                (Some(bucket), key)
            }
        }
        None => (None, None),
    }
}

/// Object key from a virtual-hosted path tail (no bucket segment).
fn object_key_from_path_tail(p: &str) -> Option<String> {
    let segments: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }
    let mut key = segments.join("/");
    if p.ends_with('/') {
        key.push('/');
    }
    Some(key)
}

/// Check If-None-Match / If-Match preconditions for PutObject.
async fn check_put_preconditions(
    state: &AppState,
    bucket: &str,
    key: &ObjectKey,
    headers: &HeaderMap,
) -> Result<(), FlashError> {
    if let Some(val) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if val.trim() == "*" {
            if state.store.get_object_meta(bucket, key).await.is_ok() {
                return Err(FlashError::PreconditionFailed);
            }
        }
    }
    if let Some(val) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) {
        match state.store.get_object_meta(bucket, key).await {
            Ok(meta) => {
                let matches = val.split(',').map(str::trim).any(|t| t == "*" || t == meta.etag);
                if !matches {
                    return Err(FlashError::PreconditionFailed);
                }
            }
            Err(FlashError::NoSuchKey) => {
                return Err(FlashError::PreconditionFailed);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Collect only control-plane and fully signed non-streaming payloads. Object
/// uploads with an unsigned or streaming payload are routed above and never
/// pass through this bounded buffer.
async fn collect_control_body(body: Body) -> Result<Bytes, FlashError> {
    const MAX_BUFFERED_BODY: usize = 16 * 1024 * 1024;
    let mut stream = body.into_data_stream();
    let mut out = BytesMut::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|error| FlashError::Internal(error.to_string()))?
    {
        if out.len().saturating_add(chunk.len()) > MAX_BUFFERED_BODY {
            return Err(FlashError::InvalidRequest(
                "request body exceeds the buffered operation limit".into(),
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

/// True when the query map is compatible with streaming PutObject.
///
/// Allows empty maps, SigV4 query-auth (`X-Amz-*`), and the AWS SDK `x-id`
/// hint. Any real S3 subresource (`acl`, `tagging`, …) forces the buffered path.
fn query_allows_streaming_put(query: &BTreeMap<String, String>) -> bool {
    query.keys().all(|k| {
        k.starts_with("X-Amz-")
            || k.starts_with("x-amz-")
            || k.eq_ignore_ascii_case("x-id")
    })
}

fn validate_buffered_integrity(headers: &HeaderMap, body: &[u8]) -> Result<(), FlashError> {
    if let Some(expected) = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
    {
        if !expected.starts_with("STREAMING-")
            && expected != "UNSIGNED-PAYLOAD"
            && expected != hash_payload(body)
        {
            return Err(FlashError::ContentSha256Mismatch);
        }
    }
    if let Some(expected) = headers
        .get("x-amz-checksum-sha256")
        .and_then(|value| value.to_str().ok())
    {
        let actual = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body));
        if expected != actual {
            return Err(FlashError::BadDigest);
        }
    }
    if let Some(expected) = headers
        .get("content-md5")
        .and_then(|value| value.to_str().ok())
    {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(expected)
            .map_err(|_| FlashError::BadDigest)?;
        let digest = md5::Md5::digest(body);
        if decoded.as_slice() != digest.as_slice() {
            return Err(FlashError::BadDigest);
        }
    }
    Ok(())
}

fn authenticate(
    state: &AppState,
    method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    raw_query: &str,
    headers: &HeaderMap,
    payload_hash: &str,
) -> Result<AuthContext, FlashError> {
    let auth = verify_request(
        method.as_str(),
        path,
        query,
        raw_query,
        headers,
        payload_hash,
        &state.config.region,
        &state.creds,
    )?;
    Ok(match auth {
        Some(a) => AuthContext::authenticated_streaming(a.key, a.streaming),
        None => AuthContext::anonymous(),
    })
}

async fn list_buckets(
    state: &AppState,
    ctx: &AuthContext,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() && state.creds.has_any_keys() {
        return Err(FlashError::AccessDenied);
    }
    state.authorizer.check_service(ctx, S3Action::ListBuckets)?;
    let buckets = state.store.list_buckets().await?;
    let (oid, oname) = ctx
        .key
        .as_ref()
        .map(|k| (k.canonical_id.as_str().to_string(), k.display_name.clone()))
        .unwrap_or_else(|| ("anonymous".into(), "anonymous".into()));
    let body = xml::list_buckets_xml(&buckets, &oid, &oname);
    state.metrics.s3_requests.with_label_values(&["GET", "200", "ListBuckets"]).inc();
    Ok(xml_ok(body, request_id))
}

async fn bucket_ops(
    state: &AppState,
    ctx: &AuthContext,
    method: &Method,
    bucket: &str,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: &Bytes,
    request_id: &str,
) -> Result<Response, FlashError> {
    if *method == Method::OPTIONS {
        return handle_options_cors(state, bucket, headers, request_id).await;
    }
    if query.contains_key("cors") {
        return bucket_cors_ops(state, ctx, method, bucket, body, request_id).await;
    }
    if query.contains_key("policy") {
        return bucket_policy_ops(state, ctx, method, bucket, body, request_id).await;
    }
    if query.contains_key("acl") {
        return bucket_acl_ops(state, ctx, method, bucket, body, headers, request_id).await;
    }
    // GetBucketLocation
    if query.contains_key("location") && *method == Method::GET {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        state.authorizer.authorize(ctx, S3Action::GetBucketLocation, Some(&info), None, policy.as_ref())?;
        let body = xml::bucket_location_xml(&state.config.region);
        state.metrics.s3_requests.with_label_values(&["GET", "200", "GetBucketLocation"]).inc();
        return Ok(xml_ok(body, request_id));
    }
    // Bucket tagging
    if query.contains_key("tagging") {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        match *method {
            Method::GET => {
                state.authorizer.authorize(ctx, S3Action::GetBucketTagging, Some(&info), None, policy.as_ref())?;
                let tags = state.store.get_bucket_tags(bucket).await?;
                state.metrics.s3_requests.with_label_values(&["GET", "200", "GetBucketTagging"]).inc();
                return Ok(xml_ok(xml::tagging_xml(&tags), request_id));
            }
            Method::PUT => {
                state.authorizer.authorize(ctx, S3Action::PutBucketTagging, Some(&info), None, policy.as_ref())?;
                let raw = std::str::from_utf8(body)
                    .map_err(|_| FlashError::InvalidRequest("invalid tagging xml".into()))?;
                let tags = xml::parse_tagging_xml(raw)?;
                state.store.put_bucket_tags(bucket, &tags).await?;
                state.metrics.s3_requests.with_label_values(&["PUT", "200", "PutBucketTagging"]).inc();
                return Ok(StatusCode::OK.into_response());
            }
            Method::DELETE => {
                state.authorizer.authorize(ctx, S3Action::DeleteBucketTagging, Some(&info), None, policy.as_ref())?;
                state.store.delete_bucket_tags(bucket).await?;
                state.metrics.s3_requests.with_label_values(&["DELETE", "204", "DeleteBucketTagging"]).inc();
                return Ok(StatusCode::NO_CONTENT.into_response());
            }
            _ => return Err(FlashError::InvalidRequest("bad tagging method".into())),
        }
    }
    // DeleteObjects (multi-object delete)
    if query.contains_key("delete") && *method == Method::POST {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        let raw = std::str::from_utf8(body)
            .map_err(|_| FlashError::InvalidRequest("invalid delete xml".into()))?;
        let (quiet, keys) = xml::parse_delete_objects_xml(raw)?;
        let mut deleted = Vec::new();
        let mut errors: Vec<(String, &str, &str)> = Vec::new();
        for key_str in &keys {
            match ObjectKey::new(key_str) {
                Ok(key) => {
                    let auth_result = state.authorizer.authorize(
                        ctx,
                        S3Action::DeleteObject,
                        Some(&info),
                        None,
                        policy.as_ref(),
                    );
                    if let Err(_) = auth_result {
                        errors.push((key_str.clone(), "AccessDenied", "Access Denied"));
                        continue;
                    }
                    match state.store.delete_object(bucket, &key).await {
                        Ok(()) => {
                            state.cache.invalidate(bucket, key.as_str()).await;
                            deleted.push(key_str.clone());
                        }
                        Err(FlashError::NoSuchKey) => {
                            deleted.push(key_str.clone());
                        }
                        Err(_) => {
                            errors.push((key_str.clone(), "InternalError", "Internal Error"));
                        }
                    }
                }
                Err(_) => {
                    errors.push((key_str.clone(), "InvalidArgument", "Invalid key"));
                }
            }
        }
        let resp_body = if quiet && errors.is_empty() {
            xml::delete_objects_result_xml(&[], &errors)
        } else {
            xml::delete_objects_result_xml(&deleted, &errors)
        };
        state.metrics.s3_requests.with_label_values(&["POST", "200", "DeleteObjects"]).inc();
        return Ok(xml_ok(resp_body, request_id));
    }
    // ListMultipartUploads
    if query.contains_key("uploads") && *method == Method::GET {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        state.authorizer.authorize(ctx, S3Action::ListBucketMultipartUploads, Some(&info), None, policy.as_ref())?;
        let prefix = query.get("prefix").map(|s| s.as_str()).unwrap_or("");
        let delimiter = query.get("delimiter").map(|s| s.as_str());
        let key_marker = query.get("key-marker").map(|s| s.as_str());
        let upload_id_marker = query.get("upload-id-marker").map(|s| s.as_str());
        let max_uploads: usize = query.get("max-uploads").and_then(|s| s.parse().ok()).unwrap_or(1000).min(1000);
        let (uploads, common_prefixes, truncated, next_key, next_upload) = state
            .store
            .list_multipart_uploads(bucket, prefix, key_marker, upload_id_marker, delimiter, max_uploads)
            .await?;
        let body = xml::list_multipart_uploads_xml(
            bucket,
            prefix,
            delimiter,
            key_marker,
            upload_id_marker,
            max_uploads,
            truncated,
            &uploads,
            &common_prefixes,
            next_key.as_deref(),
            next_upload.as_deref(),
        );
        state.metrics.s3_requests.with_label_values(&["GET", "200", "ListMultipartUploads"]).inc();
        return Ok(xml_ok(body, request_id));
    }
    // ListObjectVersions (non-versioned: current objects with VersionId=null).
    // Required so clients/s3-tests can empty buckets before DeleteBucket.
    if query.contains_key("versions") && *method == Method::GET {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        let prefix = query.get("prefix").cloned().unwrap_or_default();
        let delimiter = query.get("delimiter").map(|s| s.as_str());
        let max_keys: usize = query
            .get("max-keys")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
            .min(1000);
        let key_marker = query.get("key-marker").map(|s| s.as_str());
        let version_id_marker = query.get("version-id-marker").map(|s| s.as_str());
        let condition_ctx = PolicyConditionCtx {
            access_key: ctx.access_key(),
            s3_prefix: Some(&prefix),
            s3_delimiter: delimiter,
            s3_x_amz_acl: None,
        };
        state.authorizer.authorize_with_ctx(
            ctx,
            S3Action::ListBucket,
            Some(&info),
            None,
            policy.as_ref(),
            Some(&condition_ctx),
        )?;
        let result = state
            .store
            .list_objects(bucket, &prefix, key_marker, delimiter, max_keys)?;
        let body = xml::list_object_versions_xml(
            bucket,
            &prefix,
            delimiter,
            key_marker,
            version_id_marker,
            max_keys,
            result.truncated,
            &result.contents,
            &result.common_prefixes,
            result.next_token.as_deref(),
            info.owner.as_str(),
            &info.owner_display_name,
        );
        state
            .metrics
            .s3_requests
            .with_label_values(&["GET", "200", "ListObjectVersions"])
            .inc();
        return Ok(xml_ok(body, request_id));
    }

    match *method {
        Method::PUT => {
            if !ctx.is_authenticated() {
                return Err(FlashError::AccessDenied);
            }
            let owner = ctx.key.as_ref().unwrap();
            let info = state
                .store
                .create_bucket(
                    bucket,
                    owner.canonical_id.clone(),
                    &owner.display_name,
                    state.config.default_object_acl(),
                )
                .await?;
            let _ = info;
            state.metrics.s3_requests.with_label_values(&["PUT", "200", "CreateBucket"]).inc();
            Ok(etag_ok("", request_id))
        }
        Method::HEAD => {
            let info = state.store.get_bucket(bucket).await?;
            let policy = state.store.load_policy(bucket).await?;
            state.authorizer.authorize(
                ctx,
                S3Action::HeadBucket,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            state.metrics.s3_requests.with_label_values(&["HEAD", "200", "HeadBucket"]).inc();
            Ok(StatusCode::OK.into_response())
        }
        Method::DELETE => {
            let info = state.store.get_bucket(bucket).await?;
            let policy = state.store.load_policy(bucket).await?;
            state.authorizer.authorize(
                ctx,
                S3Action::DeleteBucket,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            state.store.delete_bucket(bucket).await?;
            state.metrics.s3_requests.with_label_values(&["DELETE", "204", "DeleteBucket"]).inc();
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Method::GET | Method::POST => {
            let info = state.store.get_bucket(bucket).await?;
            let policy = state.store.load_policy(bucket).await?;
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let delimiter = query.get("delimiter").map(|s| s.as_str());
            let encoding_type = query.get("encoding-type").map(|s| s.as_str());
            let max_keys = parse_list_max_keys(query.get("max-keys").map(|s| s.as_str()))?;
            let is_v2 = query.get("list-type").map(|s| s == "2").unwrap_or(false);
            if query.contains_key("allow-unordered")
                && delimiter.map(|d| !d.is_empty()).unwrap_or(false)
            {
                return Err(FlashError::InvalidArgument(
                    "Unordered listing not supported with delimiter".into(),
                ));
            }
            let condition_ctx = PolicyConditionCtx {
                access_key: ctx.access_key(),
                s3_prefix: Some(&prefix),
                s3_delimiter: delimiter,
                s3_x_amz_acl: None,
            };
            state.authorizer.authorize_with_ctx(
                ctx,
                S3Action::ListBucket,
                Some(&info),
                None,
                policy.as_ref(),
                Some(&condition_ctx),
            )?;

            let (start_after, continuation_token, marker) = if is_v2 {
                let ct = query
                    .get("continuation-token")
                    .map(|s| s.as_str())
                    .filter(|s| !s.is_empty());
                let sa = query
                    .get("start-after")
                    .map(|s| s.as_str())
                    .filter(|s| !s.is_empty());
                let effective = ct.or(sa);
                (effective, query.get("continuation-token").map(|s| s.as_str()), None)
            } else {
                let m = query.get("marker").map(|s| s.as_str());
                (m.filter(|s| !s.is_empty()), None, m)
            };

            let result = state.store.list_objects(bucket, &prefix, start_after, delimiter, max_keys)?;
            let owner_pair = (info.owner.as_str(), info.owner_display_name.as_str());
            // V1 always returns Owner; V2 only when fetch-owner is true.
            let include_owner = !is_v2
                || query
                    .get("fetch-owner")
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            let owner = include_owner.then_some(owner_pair);

            let body = if is_v2 {
                xml::list_objects_v2_xml(
                    bucket,
                    &prefix,
                    delimiter,
                    max_keys,
                    result.truncated,
                    &result.contents,
                    &result.common_prefixes,
                    result.next_token.as_deref(),
                    query.get("start-after").map(|s| s.as_str()),
                    continuation_token,
                    encoding_type,
                    owner,
                )
            } else {
                xml::list_objects_v1_xml(
                    bucket,
                    &prefix,
                    delimiter,
                    marker,
                    max_keys,
                    result.truncated,
                    &result.contents,
                    &result.common_prefixes,
                    result.next_token.as_deref(),
                    encoding_type,
                    owner,
                )
            };
            let label = if is_v2 { "ListObjectsV2" } else { "ListObjects" };
            state.metrics.s3_requests.with_label_values(&["GET", "200", label]).inc();
            Ok(xml_ok(body, request_id))
        }
        _ => Err(FlashError::InvalidRequest("unsupported bucket method".into())),
    }
}

async fn bucket_acl_ops(
    state: &AppState,
    ctx: &AuthContext,
    method: &Method,
    bucket: &str,
    body: &Bytes,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    let info = state.store.get_bucket(bucket).await?;
    let policy = state.store.load_policy(bucket).await?;
    match *method {
        Method::GET => {
            state.authorizer.authorize(
                ctx,
                S3Action::GetBucketAcl,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            Ok(xml_ok(xml::acl_xml(&info.acl), request_id))
        }
        Method::PUT => {
            state.authorizer.authorize(
                ctx,
                S3Action::PutBucketAcl,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            let acl = resolve_acl_from_request(headers, body, &info.acl, &info.owner_display_name)?;
            state.authorizer.ensure_can_set_acl(ctx, &acl)?;
            state.store.put_bucket_acl(bucket, acl).await?;
            Ok(StatusCode::OK.into_response())
        }
        _ => Err(FlashError::InvalidRequest("bad acl method".into())),
    }
}

async fn bucket_policy_ops(
    state: &AppState,
    ctx: &AuthContext,
    method: &Method,
    bucket: &str,
    body: &Bytes,
    request_id: &str,
) -> Result<Response, FlashError> {
    let info = state.store.get_bucket(bucket).await?;
    let policy = state.store.load_policy(bucket).await?;
    match *method {
        Method::GET => {
            state.authorizer.authorize(
                ctx,
                S3Action::GetBucketPolicy,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            let raw = state.store.get_bucket_policy(bucket).await?;
            Ok(json_ok(raw, request_id))
        }
        Method::PUT => {
            state.authorizer.authorize(
                ctx,
                S3Action::PutBucketPolicy,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            let raw = std::str::from_utf8(body)
                .map_err(|_| FlashError::MalformedPolicy)?;
            state.store.put_bucket_policy(bucket, raw).await?;
            Ok(StatusCode::OK.into_response())
        }
        Method::DELETE => {
            state.authorizer.authorize(
                ctx,
                S3Action::DeleteBucketPolicy,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            state.store.delete_bucket_policy(bucket).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(FlashError::InvalidRequest("bad policy method".into())),
    }
}

async fn bucket_cors_ops(
    state: &AppState,
    ctx: &AuthContext,
    method: &Method,
    bucket: &str,
    body: &Bytes,
    request_id: &str,
) -> Result<Response, FlashError> {
    let info = state.store.get_bucket(bucket).await?;
    let policy = state.store.load_policy(bucket).await?;
    match *method {
        Method::GET => {
            state.authorizer.authorize(
                ctx,
                S3Action::GetBucketCors,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            let raw = state.store.get_bucket_cors(bucket).await?;
            state
                .metrics
                .s3_requests
                .with_label_values(&["GET", "200", "GetBucketCors"])
                .inc();
            Ok(xml_ok(raw, request_id))
        }
        Method::PUT => {
            state.authorizer.authorize(
                ctx,
                S3Action::PutBucketCors,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            let raw = std::str::from_utf8(body)
                .map_err(|_| FlashError::MalformedCORSConfiguration)?;
            let cors = xml::parse_cors_xml(raw)?;
            let canonical = xml::cors_xml(&cors);
            state.store.put_bucket_cors(bucket, &canonical).await?;
            state
                .metrics
                .s3_requests
                .with_label_values(&["PUT", "200", "PutBucketCors"])
                .inc();
            Ok(StatusCode::OK.into_response())
        }
        Method::DELETE => {
            state.authorizer.authorize(
                ctx,
                S3Action::DeleteBucketCors,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            state.store.delete_bucket_cors(bucket).await?;
            state
                .metrics
                .s3_requests
                .with_label_values(&["DELETE", "204", "DeleteBucketCors"])
                .inc();
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(FlashError::InvalidRequest("bad cors method".into())),
    }
}

#[allow(clippy::too_many_arguments)]
async fn object_ops(
    state: &AppState,
    ctx: &AuthContext,
    method: &Method,
    bucket: &str,
    key: &ObjectKey,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    body: Bytes,
    request_id: &str,
) -> Result<Response, FlashError> {
    if *method == Method::OPTIONS {
        return handle_options_cors(state, bucket, headers, request_id).await;
    }
    // Multipart
    if query.contains_key("uploads") && *method == Method::POST {
        return create_multipart(state, ctx, bucket, key, headers, request_id).await;
    }
    if let Some(upload_id) = query.get("uploadId") {
        if query.contains_key("partNumber") && *method == Method::PUT {
            // UploadPartCopy takes precedence when a copy source is present.
            if headers.contains_key("x-amz-copy-source") {
                let pn: i32 = query
                    .get("partNumber")
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| FlashError::InvalidRequest("partNumber".into()))?;
                if !ctx.is_authenticated() {
                    return Err(FlashError::AccessDenied);
                }
                let copy_src = headers
                    .get("x-amz-copy-source")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| FlashError::InvalidRequest("missing copy source".into()))?;
                let src = copy_src.trim_start_matches('/');
                let (src_bucket, src_key_raw) = src
                    .split_once('/')
                    .ok_or_else(|| FlashError::InvalidRequest("bad copy source".into()))?;
                let src_key =
                    ObjectKey::new(urlencoding::decode(src_key_raw).unwrap_or_default().as_ref())
                        .map_err(|_| FlashError::InvalidObjectName)?;
                let range = headers
                    .get("x-amz-copy-source-range")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| {
                        let s = v.strip_prefix("bytes=")?;
                        let (start, end) = s.split_once('-')?;
                        Some((start.parse::<u64>().ok()?, end.parse::<u64>().ok()?))
                    });
                let (etag, last_modified) = state
                    .store
                    .upload_part_copy(
                        bucket,
                        upload_id,
                        pn,
                        src_bucket,
                        &src_key,
                        range,
                        &state.sse_key,
                    )
                    .await?;
                return Ok(xml_ok(
                    xml::copy_part_result_xml(&etag, &last_modified),
                    request_id,
                ));
            }
            let pn: i32 = query
                .get("partNumber")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| FlashError::InvalidRequest("partNumber".into()))?;
            return upload_part(state, ctx, bucket, upload_id, pn, body, request_id).await;
        }
        if *method == Method::POST {
            return complete_multipart(state, ctx, bucket, upload_id, &body, request_id).await;
        }
        if *method == Method::DELETE {
            state.store.abort_multipart(bucket, upload_id).await?;
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        if *method == Method::GET {
            let (k, parts) = state.store.list_parts(bucket, upload_id).await?;
            return Ok(xml_ok(
                xml::list_parts_xml(bucket, &k, upload_id, &parts),
                request_id,
            ));
        }
    }

    if query.contains_key("acl") {
        return object_acl_ops(state, ctx, method, bucket, key, &body, headers, request_id).await;
    }

    // Object tagging
    if query.contains_key("tagging") {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        match *method {
            Method::GET => {
                let meta = state.store.get_object_meta(bucket, key).await?;
                state.authorizer.authorize(ctx, S3Action::GetObjectTagging, Some(&info), Some(&meta), policy.as_ref())?;
                let tags = state.store.get_object_tags(bucket, key).await?;
                return Ok(xml_ok(xml::tagging_xml(&tags), request_id));
            }
            Method::PUT => {
                state.authorizer.authorize(ctx, S3Action::PutObjectTagging, Some(&info), None, policy.as_ref())?;
                let raw = std::str::from_utf8(&body)
                    .map_err(|_| FlashError::InvalidRequest("invalid tagging xml".into()))?;
                let tags = xml::parse_tagging_xml(raw)?;
                state.store.put_object_tags(bucket, key, &tags).await?;
                return Ok(StatusCode::OK.into_response());
            }
            Method::DELETE => {
                state.authorizer.authorize(ctx, S3Action::DeleteObjectTagging, Some(&info), None, policy.as_ref())?;
                state.store.delete_object_tags(bucket, key).await?;
                return Ok(StatusCode::NO_CONTENT.into_response());
            }
            _ => return Err(FlashError::InvalidRequest("bad tagging method".into())),
        }
    }

    // UploadPartCopy is handled earlier (before plain UploadPart).

    match *method {
        Method::PUT => {
            if let Some(copy_src) = headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok()) {
                return copy_object(state, ctx, bucket, key, copy_src, headers, request_id).await;
            }
            put_object(state, ctx, bucket, key, body, headers, request_id).await
        }
        Method::GET => get_object(state, ctx, bucket, key, headers, request_id).await,
        Method::HEAD => head_object(state, ctx, bucket, key, headers, request_id).await,
        Method::DELETE => {
            let info = state.store.get_bucket(bucket).await?;
            let meta = state.store.get_object_meta(bucket, key).await?;
            let policy = state.store.load_policy(bucket).await?;
            state.authorizer.authorize(
                ctx,
                S3Action::DeleteObject,
                Some(&info),
                Some(&meta),
                policy.as_ref(),
            )?;
            state.store.delete_object(bucket, key).await?;
            state.cache.invalidate(bucket, key.as_str()).await;
            state.metrics.s3_requests.with_label_values(&["DELETE", "204", "DeleteObject"]).inc();
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(FlashError::InvalidRequest("unsupported object method".into())),
    }
}

async fn object_ops_stream(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    query: &BTreeMap<String, String>,
    headers: &HeaderMap,
    reader: impl tokio::io::AsyncRead + Unpin,
    request_id: &str,
) -> Result<Response, FlashError> {
    if let Some(upload_id) = query.get("uploadId") {
        if query.contains_key("partNumber") {
            let part_number: i32 = query
                .get("partNumber")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| FlashError::InvalidRequest("partNumber".into()))?;
            return upload_part_stream(
                state,
                ctx,
                bucket,
                upload_id,
                part_number,
                reader,
                request_id,
            )
            .await;
        }
    }
    put_object_stream(state, ctx, bucket, key, reader, headers, request_id).await
}

async fn put_object(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    body: Bytes,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        state.authorizer.authorize(
            ctx,
            S3Action::PutObject,
            Some(&info),
            None,
            policy.as_ref(),
        )?;
    } else {
        let info = state.store.get_bucket(bucket).await?;
        let policy = state.store.load_policy(bucket).await?;
        let obj = state.store.get_object_meta(bucket, key).await.ok();
        state.authorizer.authorize(
            ctx,
            S3Action::PutObject,
            Some(&info),
            obj.as_ref(),
            policy.as_ref(),
        )?;
    }

    // Conditional PutObject preconditions
    check_put_preconditions(state, bucket, key, headers).await?;

    let info = state.store.get_bucket(bucket).await?;
    let owner = ctx.key.as_ref().ok_or(FlashError::AccessDenied)?;
    let mut opts = put_object_opts(headers, owner, info.default_object_acl);

    // Checksums verification and collection
    let computed_checksums = verify_checksums(&body, headers)?;
    for (k, v) in &computed_checksums {
        opts.checksums.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // SSE-S3 encryption
    let final_body = if request_wants_sse_s3(headers) {
        let plaintext_md5 = md5_etag_of(&body);
        let (ciphertext, nonce) = sse_encrypt(&state.sse_key, &body)?;
        opts.sse_s3 = true;
        opts.sse_nonce = Some(nonce);
        opts.plaintext_size = Some(body.len() as u64);
        opts.etag_override = Some(plaintext_md5);
        Bytes::from(ciphertext)
    } else {
        body.clone()
    };

    let meta = state
        .store
        .put_object(bucket, key, final_body.clone(), opts)
        .await?;

    if meta.size <= state.cache.object_max_bytes() {
        if meta.sse_s3 {
            state.cache.invalidate(bucket, key.as_str()).await;
        } else {
            state.cache.insert(bucket, key.as_str(), final_body).await;
        }
    } else {
        state.cache.invalidate(bucket, key.as_str()).await;
    }

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, &meta.etag)
        .header("x-amz-request-id", request_id);
    if meta.sse_s3 {
        resp = resp.header("x-amz-server-side-encryption", "AES256");
    }
    state.metrics.s3_requests.with_label_values(&["PUT", "200", "PutObject"]).inc();
    Ok(resp.body(Body::empty()).unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

async fn put_object_stream(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    mut reader: impl tokio::io::AsyncRead + Unpin,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    use tokio::io::AsyncReadExt;

    // Signed requests usually hit this streaming path. When the client declares
    // flexible checksums or SSE-S3, buffer the body so we can verify/encrypt.
    let needs_buffer = request_wants_sse_s3(headers)
        || headers.keys().any(|name| name.as_str().starts_with("x-amz-checksum-"));
    if needs_buffer {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(|e| FlashError::Internal(e.to_string()))?;
        return put_object(
            state,
            ctx,
            bucket,
            key,
            Bytes::from(buf),
            headers,
            request_id,
        )
        .await;
    }

    let info = state.store.get_bucket(bucket).await?;
    let policy = state.store.load_policy(bucket).await?;
    let object = if ctx.is_authenticated() {
        state.store.get_object_meta(bucket, key).await.ok()
    } else {
        None
    };
    state.authorizer.authorize(
        ctx,
        S3Action::PutObject,
        Some(&info),
        object.as_ref(),
        policy.as_ref(),
    )?;

    check_put_preconditions(state, bucket, key, headers).await?;

    let owner = ctx.key.as_ref().ok_or(FlashError::AccessDenied)?;
    let opts = put_object_opts(headers, owner, info.default_object_acl);
    let meta = state
        .store
        .put_object_stream(bucket, key, reader, opts)
        .await?;
    if meta.size <= state.cache.object_max_bytes() {
        let (_, body) = state.store.read_object_bytes(bucket, key).await?;
        state.cache.insert(bucket, key.as_str(), body).await;
    } else {
        state.cache.invalidate(bucket, key.as_str()).await;
    }
    state.metrics.s3_requests.with_label_values(&["PUT", "200", "PutObject"]).inc();
    Ok(etag_ok(&meta.etag, request_id))
}

async fn get_object(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    let info = state.store.get_bucket(bucket).await?;
    let meta = state.store.get_object_meta(bucket, key).await?;
    let policy = state.store.load_policy(bucket).await?;
    state.authorizer.authorize(
        ctx,
        S3Action::GetObject,
        Some(&info),
        Some(&meta),
        policy.as_ref(),
    )?;

    if let Some(response) = conditional_object_response(&meta, headers, request_id) {
        return Ok(response);
    }

    let range = match requested_range(headers, meta.size) {
        Ok(range) => range,
        Err(RangeError::Multiple) => {
            return Err(FlashError::InvalidRequest(
                "multiple byte ranges are not supported".into(),
            ));
        }
        Err(RangeError::Unsatisfiable) => {
            return Ok(range_not_satisfiable_response(meta.size, request_id));
        }
    };

    // SSE-S3: decrypt and serve in-memory
    if meta.sse_s3 {
        let (meta, plaintext) = state.store.read_object_plaintext(bucket, key, &state.sse_key).await?;
        state.metrics.s3_requests.with_label_values(&["GET", "200", "GetObject"]).inc();
        if let Some(range) = range {
            let bytes = plaintext.slice(range.start as usize..=range.end as usize);
            return Ok(partial_object_response(&meta, Body::from(bytes), range, request_id));
        }
        return Ok(object_response(&meta, Body::from(plaintext), request_id));
    }

    // Cache hit for small objects
    if let Some(cached) = state.cache.get(bucket, key.as_str()).await {
        state.metrics.s3_requests.with_label_values(&["GET", "200", "GetObject"]).inc();
        if let Some(range) = range {
            let bytes = cached.slice(range.start as usize..=range.end as usize);
            return Ok(partial_object_response(&meta, Body::from(bytes), range, request_id));
        }
        return Ok(object_response(&meta, Body::from(cached), request_id));
    }

    if range.is_none() && meta.size <= state.cache.object_max_bytes() {
        let (meta, file) = state.store.open_object_file(bucket, key).await?;
        let cache = state.cache.clone();
        let bucket = bucket.to_string();
        let key = key.as_str().to_string();
        let stream = futures::stream::unfold(
            (ReaderStream::new(file), Vec::new(), false),
            move |(mut reader, mut buffered, failed)| {
                let cache = cache.clone();
                let bucket = bucket.clone();
                let key = key.clone();
                async move {
                    if failed {
                        return None;
                    }
                    match reader.next().await {
                        Some(Ok(chunk)) => {
                            buffered.extend_from_slice(&chunk);
                            Some((Ok::<Bytes, std::io::Error>(chunk), (reader, buffered, false)))
                        }
                        Some(Err(error)) => Some((Err(error), (reader, buffered, true))),
                        None => {
                            cache.insert(&bucket, &key, Bytes::from(buffered)).await;
                            None
                        }
                    }
                }
            },
        );
        state.metrics.disk_read_bytes.inc_by(meta.size);
        state.metrics.s3_requests.with_label_values(&["GET", "200", "GetObject"]).inc();
        return Ok(object_response(&meta, Body::from_stream(stream), request_id));
    }

    let (file, response_size) = if let Some(range) = range {
        (
            state
                .store
                .open_object_range_file(bucket, key, range.start)
                .await?,
            range.len(),
        )
    } else {
        (state.store.open_object_file(bucket, key).await?.1, meta.size)
    };
    let stream = ReaderStream::new(file.take(response_size));
    let body = Body::from_stream(stream);
    state.metrics.disk_read_bytes.inc_by(response_size);
    state.metrics.s3_requests.with_label_values(&["GET", "200", "GetObject"]).inc();
    if let Some(range) = range {
        Ok(partial_object_response(&meta, body, range, request_id))
    } else {
        Ok(object_response(&meta, body, request_id))
    }
}

async fn head_object(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    let info = state.store.get_bucket(bucket).await?;
    let meta = state.store.get_object_meta(bucket, key).await?;
    let policy = state.store.load_policy(bucket).await?;
    state.authorizer.authorize(
        ctx,
        S3Action::GetObject,
        Some(&info),
        Some(&meta),
        policy.as_ref(),
    )?;
    if let Some(response) = conditional_object_response(&meta, headers, request_id) {
        return Ok(response);
    }
    state.metrics.s3_requests.with_label_values(&["HEAD", "200", "HeadObject"]).inc();
    match requested_range(headers, meta.size) {
        Ok(Some(range)) => Ok(partial_object_response(
            &meta,
            Body::empty(),
            range,
            request_id,
        )),
        Ok(None) => Ok(object_response(&meta, Body::empty(), request_id)),
        Err(RangeError::Multiple) => Err(FlashError::InvalidRequest(
            "multiple byte ranges are not supported".into(),
        )),
        Err(RangeError::Unsatisfiable) => Ok(range_not_satisfiable_response(meta.size, request_id)),
    }
}

async fn copy_object(
    state: &AppState,
    ctx: &AuthContext,
    dst_bucket: &str,
    dst_key: &ObjectKey,
    copy_src: &str,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() {
        return Err(FlashError::AccessDenied);
    }
    let src = copy_src.trim_start_matches('/');
    let (src_bucket, src_key_raw) = src
        .split_once('/')
        .ok_or_else(|| FlashError::InvalidRequest("bad copy source".into()))?;
    let src_key = ObjectKey::new(urlencoding::decode(src_key_raw).unwrap_or_default().as_ref())
        .map_err(|_| FlashError::InvalidObjectName)?;

    let src_info = state.store.get_bucket(src_bucket).await?;
    let src_meta = state.store.get_object_meta(src_bucket, &src_key).await?;
    let src_policy = state.store.load_policy(src_bucket).await?;
    state.authorizer.authorize(
        ctx,
        S3Action::GetObject,
        Some(&src_info),
        Some(&src_meta),
        src_policy.as_ref(),
    )?;

    // Conditional copy-source preconditions
    if let Some(val) = headers.get("x-amz-copy-source-if-match").and_then(|v| v.to_str().ok()) {
        let matches = val.split(',').map(str::trim).any(|t| t == "*" || t == src_meta.etag);
        if !matches {
            return Err(FlashError::PreconditionFailed);
        }
    }
    if let Some(val) = headers.get("x-amz-copy-source-if-none-match").and_then(|v| v.to_str().ok()) {
        let matches = val.split(',').map(str::trim).any(|t| t == "*" || t == src_meta.etag);
        if matches {
            return Err(FlashError::PreconditionFailed);
        }
    }
    if let Some(val) = headers.get("x-amz-copy-source-if-modified-since").and_then(|v| v.to_str().ok()) {
        if let (Ok(since), Ok(modified)) = (
            DateTime::parse_from_rfc2822(val),
            DateTime::parse_from_rfc3339(&src_meta.last_modified),
        ) {
            if modified <= since {
                return Err(FlashError::PreconditionFailed);
            }
        }
    }
    if let Some(val) = headers.get("x-amz-copy-source-if-unmodified-since").and_then(|v| v.to_str().ok()) {
        if let (Ok(since), Ok(modified)) = (
            DateTime::parse_from_rfc2822(val),
            DateTime::parse_from_rfc3339(&src_meta.last_modified),
        ) {
            if modified > since {
                return Err(FlashError::PreconditionFailed);
            }
        }
    }

    let dst_info = state.store.get_bucket(dst_bucket).await?;
    let dst_policy = state.store.load_policy(dst_bucket).await?;
    state.authorizer.authorize(
        ctx,
        S3Action::PutObject,
        Some(&dst_info),
        None,
        dst_policy.as_ref(),
    )?;

    let owner = ctx.key.as_ref().unwrap();
    let canned = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .and_then(CannedAcl::parse);

    // metadata-directive: REPLACE uses request headers; COPY (default) keeps src
    let metadata_directive = headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY");

    let (user_meta, content_type, content_encoding, cache_control, content_disposition, content_language, expires, checksums) =
        if metadata_directive.eq_ignore_ascii_case("REPLACE") {
            let hv = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(ToOwned::to_owned);
            (
                extract_user_meta(headers),
                hv("content-type"),
                hv("content-encoding"),
                hv("cache-control"),
                hv("content-disposition"),
                hv("content-language"),
                hv("expires"),
                std::collections::HashMap::new(),
            )
        } else {
            (
                src_meta.user_meta.clone(),
                Some(src_meta.content_type.clone()),
                src_meta.content_encoding.clone(),
                src_meta.cache_control.clone(),
                src_meta.content_disposition.clone(),
                src_meta.content_language.clone(),
                src_meta.expires.clone(),
                src_meta.checksums.clone(),
            )
        };

    // If SSE is needed (src encrypted or dst wants SSE): read plaintext, then put with encrypt
    let dst_wants_sse = request_wants_sse_s3(headers);
    if src_meta.sse_s3 || dst_wants_sse {
        let (_src_m, plaintext) = state.store.read_object_plaintext(src_bucket, &src_key, &state.sse_key).await?;
        let mut opts = PutObjectOpts {
            content_type: content_type.or(Some(src_meta.content_type.clone())),
            canned_acl: canned,
            acl: None,
            owner: owner.canonical_id.clone(),
            owner_display_name: owner.display_name.clone(),
            default_object_acl: dst_info.default_object_acl,
            user_meta,
            content_encoding,
            cache_control,
            content_disposition,
            content_language,
            expires,
            checksums,
            sse_s3: false,
            sse_nonce: None,
            plaintext_size: None,
            etag_override: None,
        };
        let final_body = if dst_wants_sse {
            let plaintext_md5 = md5_etag_of(&plaintext);
            let (ciphertext, nonce) = sse_encrypt(&state.sse_key, &plaintext)?;
            opts.sse_s3 = true;
            opts.sse_nonce = Some(nonce);
            opts.plaintext_size = Some(plaintext.len() as u64);
            opts.etag_override = Some(plaintext_md5);
            Bytes::from(ciphertext)
        } else {
            plaintext
        };
        let meta = state.store.put_object(dst_bucket, dst_key, final_body, opts).await?;
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>"#,
            xml_escape(&meta.last_modified),
            xml_escape(&meta.etag)
        );
        state.metrics.s3_requests.with_label_values(&["PUT", "200", "CopyObject"]).inc();
        return Ok(xml_ok(body, request_id));
    }

    let opts = PutObjectOpts {
        content_type: content_type.or(Some(src_meta.content_type.clone())),
        canned_acl: canned,
        acl: None,
        owner: owner.canonical_id.clone(),
        owner_display_name: owner.display_name.clone(),
        default_object_acl: dst_info.default_object_acl,
        user_meta,
        content_encoding,
        cache_control,
        content_disposition,
        content_language,
        expires,
        checksums,
        sse_s3: false,
        sse_nonce: None,
        plaintext_size: None,
        etag_override: None,
    };
    let meta = state
        .store
        .copy_object(src_bucket, &src_key, dst_bucket, dst_key, opts)
        .await?;
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>"#,
        xml_escape(&meta.last_modified),
        xml_escape(&meta.etag)
    );
    state.metrics.s3_requests.with_label_values(&["PUT", "200", "CopyObject"]).inc();
    Ok(xml_ok(body, request_id))
}

async fn object_acl_ops(
    state: &AppState,
    ctx: &AuthContext,
    method: &Method,
    bucket: &str,
    key: &ObjectKey,
    body: &Bytes,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    let info = state.store.get_bucket(bucket).await?;
    let meta = state.store.get_object_meta(bucket, key).await?;
    let policy = state.store.load_policy(bucket).await?;
    match *method {
        Method::GET => {
            state.authorizer.authorize(
                ctx,
                S3Action::GetObjectAcl,
                Some(&info),
                Some(&meta),
                policy.as_ref(),
            )?;
            Ok(xml_ok(xml::acl_xml(&meta.acl), request_id))
        }
        Method::PUT => {
            state.authorizer.authorize(
                ctx,
                S3Action::PutObjectAcl,
                Some(&info),
                Some(&meta),
                policy.as_ref(),
            )?;
            let acl = resolve_acl_from_request(headers, body, &meta.acl, &meta.owner_display_name)?;
            state.authorizer.ensure_can_set_acl(ctx, &acl)?;
            state.store.put_object_acl(bucket, key, acl).await?;
            Ok(StatusCode::OK.into_response())
        }
        _ => Err(FlashError::InvalidRequest("bad object acl method".into())),
    }
}

async fn create_multipart(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() {
        return Err(FlashError::AccessDenied);
    }
    let info = state.store.get_bucket(bucket).await?;
    let policy = state.store.load_policy(bucket).await?;
    state.authorizer.authorize(
        ctx,
        S3Action::PutObject,
        Some(&info),
        None,
        policy.as_ref(),
    )?;
    let owner = ctx.key.as_ref().unwrap();
    let canned = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .and_then(CannedAcl::parse);
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let upload_id = state
        .store
        .create_multipart(
            bucket,
            key,
            owner.canonical_id.clone(),
            &owner.display_name,
            ct,
            canned,
        )
        .await?;
    Ok(xml_ok(
        xml::initiate_multipart_xml(bucket, key.as_str(), &upload_id),
        request_id,
    ))
}

async fn upload_part(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    upload_id: &str,
    part_number: i32,
    body: Bytes,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() {
        return Err(FlashError::AccessDenied);
    }
    let etag = state
        .store
        .upload_part(bucket, upload_id, part_number, body)
        .await?;
    Ok(etag_ok(&etag, request_id))
}

async fn upload_part_stream(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    upload_id: &str,
    part_number: i32,
    reader: impl tokio::io::AsyncRead + Unpin,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() {
        return Err(FlashError::AccessDenied);
    }
    let etag = state
        .store
        .upload_part_stream(bucket, upload_id, part_number, reader)
        .await?;
    Ok(etag_ok(&etag, request_id))
}

async fn complete_multipart(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    upload_id: &str,
    body: &Bytes,
    request_id: &str,
) -> Result<Response, FlashError> {
    if !ctx.is_authenticated() {
        return Err(FlashError::AccessDenied);
    }
    let xml_body = std::str::from_utf8(body)
        .map_err(|_| FlashError::InvalidRequest("bad xml".into()))?;
    let parts = xml::parse_complete_multipart(xml_body)?;
    let info = state.store.get_bucket(bucket).await?;
    let meta = state
        .store
        .complete_multipart(bucket, upload_id, &parts, info.default_object_acl)
        .await?;
    Ok(xml_ok(
        xml::complete_multipart_xml(bucket, &meta.key, &meta.etag),
        request_id,
    ))
}

fn object_response(meta: &crate::storage::ObjectMeta, body: Body, request_id: &str) -> Response {
    object_response_with_status(meta, body, StatusCode::OK, meta.size, None, request_id)
}

fn conditional_object_response(
    meta: &crate::storage::ObjectMeta,
    headers: &HeaderMap,
    request_id: &str,
) -> Option<Response> {
    let etag_matches = |value: &str| {
        value
            .split(',')
            .map(str::trim)
            .any(|tag| tag == "*" || tag.trim_start_matches("W/") == meta.etag)
    };
    if let Some(value) = headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok()) {
        if !etag_matches(value) {
            return Some(precondition_response(StatusCode::PRECONDITION_FAILED, meta, request_id));
        }
    } else if let Some(value) = headers
        .get(header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    {
        if let (Ok(since), Ok(modified)) = (
            DateTime::parse_from_rfc2822(value),
            DateTime::parse_from_rfc3339(&meta.last_modified),
        ) {
            if modified > since {
                return Some(precondition_response(
                    StatusCode::PRECONDITION_FAILED,
                    meta,
                    request_id,
                ));
            }
        }
    }
    if let Some(value) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        if etag_matches(value) {
            return Some(precondition_response(StatusCode::NOT_MODIFIED, meta, request_id));
        }
    } else if let Some(value) = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    {
        if let (Ok(since), Ok(modified)) = (
            DateTime::parse_from_rfc2822(value),
            DateTime::parse_from_rfc3339(&meta.last_modified),
        ) {
            if modified <= since {
                return Some(precondition_response(StatusCode::NOT_MODIFIED, meta, request_id));
            }
        }
    }
    None
}

fn precondition_response(
    status: StatusCode,
    meta: &crate::storage::ObjectMeta,
    request_id: &str,
) -> Response {
    Response::builder()
        .status(status)
        .header(header::ETAG, &meta.etag)
        .header(header::LAST_MODIFIED, http_date(&meta.last_modified))
        .header("x-amz-request-id", request_id)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn partial_object_response(
    meta: &crate::storage::ObjectMeta,
    body: Body,
    range: ByteRange,
    request_id: &str,
) -> Response {
    let content_range = format!("bytes {}-{}/{}", range.start, range.end, meta.size);
    object_response_with_status(
        meta,
        body,
        StatusCode::PARTIAL_CONTENT,
        range.len(),
        Some(content_range),
        request_id,
    )
}

fn object_response_with_status(
    meta: &crate::storage::ObjectMeta,
    body: Body,
    status: StatusCode,
    content_length: u64,
    content_range: Option<String>,
    request_id: &str,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, &meta.content_type)
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::ETAG, &meta.etag)
        .header(header::LAST_MODIFIED, http_date(&meta.last_modified))
        .header("x-amz-request-id", request_id)
        .header("Accept-Ranges", "bytes");
    if let Some(content_range) = content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    if let Some(value) = &meta.content_encoding {
        builder = builder.header(header::CONTENT_ENCODING, value);
    }
    if meta.sse_s3 {
        builder = builder.header("x-amz-server-side-encryption", "AES256");
    }
    for (name, value) in [
        ("cache-control", meta.cache_control.as_deref()),
        ("content-disposition", meta.content_disposition.as_deref()),
        ("content-language", meta.content_language.as_deref()),
        ("expires", meta.expires.as_deref()),
    ] {
        if let Some(value) = value {
            builder = builder.header(name, value);
        }
    }
    for (name, value) in &meta.user_meta {
        if let Some(hv) = meta_to_header_value(value) {
            builder = builder.header(format!("x-amz-meta-{name}"), hv);
        }
    }
    for (name, value) in &meta.checksums {
        builder = builder.header(name, value);
    }
    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn range_not_satisfiable_response(size: u64, request_id: &str) -> Response {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
        .header("x-amz-request-id", request_id)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[derive(Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

enum RangeError {
    Multiple,
    Unsatisfiable,
}

fn requested_range(headers: &HeaderMap, size: u64) -> Result<Option<ByteRange>, RangeError> {
    let Some(value) = headers.get(header::RANGE) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| RangeError::Unsatisfiable)?;
    let spec = value.strip_prefix("bytes=").ok_or(RangeError::Unsatisfiable)?;
    if spec.contains(',') {
        return Err(RangeError::Multiple);
    }
    let (start, end) = spec.split_once('-').ok_or(RangeError::Unsatisfiable)?;
    if start.is_empty() {
        let suffix: u64 = end.parse().map_err(|_| RangeError::Unsatisfiable)?;
        if suffix == 0 || size == 0 {
            return Err(RangeError::Unsatisfiable);
        }
        let length = suffix.min(size);
        return Ok(Some(ByteRange {
            start: size - length,
            end: size - 1,
        }));
    }
    let start: u64 = start.parse().map_err(|_| RangeError::Unsatisfiable)?;
    if start >= size {
        return Err(RangeError::Unsatisfiable);
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        let end: u64 = end.parse().map_err(|_| RangeError::Unsatisfiable)?;
        if end < start {
            return Err(RangeError::Unsatisfiable);
        }
        end.min(size - 1)
    };
    Ok(Some(ByteRange { start, end }))
}

/// Convert persisted RFC3339 metadata into the HTTP-date syntax required by
/// RFC 7231 and expected by S3 SDK deserializers.
fn http_date(timestamp: &str) -> String {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|date| date.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

fn xml_ok(body: String, request_id: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .header(
            HeaderName::from_static("x-amz-request-id"),
            HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
        )
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn json_ok(body: String, request_id: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            HeaderName::from_static("x-amz-request-id"),
            HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
        )
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn etag_ok(etag: &str, request_id: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag)
        .header(
            HeaderName::from_static("x-amz-request-id"),
            HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
        )
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn load_bucket_cors(
    state: &AppState,
    bucket: &str,
) -> Result<Option<CorsConfiguration>, FlashError> {
    match state.store.load_cors_raw(bucket).await? {
        Some(raw) => Ok(Some(xml::parse_cors_xml(&raw)?)),
        None => Ok(None),
    }
}

/// Browser CORS preflight (`OPTIONS`) against a bucket/object path.
///
/// Does not require SigV4; evaluates the bucket CORS configuration only.
async fn handle_options_cors(
    state: &AppState,
    bucket: &str,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
    let _ = state.store.get_bucket(bucket).await?;
    let cors = load_bucket_cors(state, bucket).await?;
    let Some(cors) = cors else {
        return Err(FlashError::AccessDenied);
    };

    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or(FlashError::AccessDenied)?;
    let req_method = headers
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            FlashError::InvalidRequest("missing Access-Control-Request-Method".into())
        })?;
    let req_headers = headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let rule = cors
        .find_matching_rule(origin, req_method, req_headers)
        .ok_or(FlashError::AccessDenied)?;

    state
        .metrics
        .s3_requests
        .with_label_values(&["OPTIONS", "200", "CORSPreflight"])
        .inc();
    Ok(preflight_response(rule, origin, req_method, req_headers, request_id))
}

fn preflight_response(
    rule: &CorsRule,
    origin: &str,
    req_method: &str,
    req_headers: &str,
    request_id: &str,
) -> Response {
    let allow_origin = rule.allow_origin_value(origin);
    let allow_methods = req_method.to_ascii_uppercase();
    let allow_headers = allowed_request_headers(&rule.allowed_headers, req_headers);
    let expose = rule.expose_headers.join(",");
    let max_age = rule.max_age_seconds.map(|v| v.to_string());

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            HeaderName::from_static("x-amz-request-id"),
            HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
        )
        .header(
            header::VARY,
            "Origin, Access-Control-Request-Headers, Access-Control-Request-Method",
        )
        .header(
            HeaderName::from_static("access-control-allow-origin"),
            allow_origin,
        )
        .header(
            HeaderName::from_static("access-control-allow-methods"),
            allow_methods,
        );

    if !allow_headers.is_empty() {
        builder = builder.header(
            HeaderName::from_static("access-control-allow-headers"),
            allow_headers.join(","),
        );
    }
    if !expose.is_empty() {
        builder = builder.header(
            HeaderName::from_static("access-control-expose-headers"),
            expose,
        );
    }
    if let Some(max_age) = max_age {
        builder = builder.header(HeaderName::from_static("access-control-max-age"), max_age);
    }

    builder
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn maybe_apply_cors_headers(
    state: &AppState,
    bucket: &str,
    method: &str,
    origin: &str,
    resp: &mut Response,
) {
    let Ok(Some(cors)) = load_bucket_cors(state, bucket).await else {
        return;
    };
    let Some(rule) = cors.find_matching_rule(origin, method, "") else {
        return;
    };
    let headers = resp.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&rule.allow_origin_value(origin)) {
        headers.insert(
            HeaderName::from_static("access-control-allow-origin"),
            value,
        );
    }
    if !rule.expose_headers.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&rule.expose_headers.join(",")) {
            headers.insert(
                HeaderName::from_static("access-control-expose-headers"),
                value,
            );
        }
    }
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
}

fn parse_query(q: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        let mut it = pair.splitn(2, '=');
        let k = urlencoding::decode(it.next().unwrap_or(""))
            .unwrap_or_default()
            .to_string();
        let v = urlencoding::decode(it.next().unwrap_or(""))
            .unwrap_or_default()
            .to_string();
        map.insert(k, v);
    }
    map
}

fn parse_list_max_keys(raw: Option<&str>) -> Result<usize, FlashError> {
    match raw {
        None | Some("") => Ok(1000),
        Some(s) => {
            let n: i64 = s.parse().map_err(|_| {
                FlashError::InvalidArgument(format!("Provided max-keys not an integer or within integer range: {s}"))
            })?;
            if n < 0 {
                return Err(FlashError::InvalidArgument(format!(
                    "Argument max-keys must be an integer between 0 and 2147483647"
                )));
            }
            Ok((n as usize).min(1000))
        }
    }
}

/// Read a header value as a string, including opaque / ISO-8859-1 bytes.
///
/// `HeaderValue::to_str` only accepts visible ASCII. Prefer UTF-8 (botocore may
/// send Unicode metadata as UTF-8 on the wire); fall back to ISO-8859-1.
fn header_value_string(value: &HeaderValue) -> String {
    match std::str::from_utf8(value.as_bytes()) {
        Ok(s) => s.to_string(),
        Err(_) => value.as_bytes().iter().map(|&b| b as char).collect(),
    }
}

/// Encode a stored metadata string back to an HTTP header value.
///
/// Emit ISO-8859-1 when all codepoints fit in a byte so Latin-1 clients
/// (botocore metadata parsing) round-trip Unicode like `é` correctly.
fn meta_to_header_value(value: &str) -> Option<HeaderValue> {
    if value.is_ascii() {
        return HeaderValue::from_str(value).ok();
    }
    if value.chars().all(|c| u32::from(c) <= 0xFF) {
        let bytes: Vec<u8> = value.chars().map(|c| u32::from(c) as u8).collect();
        return HeaderValue::from_bytes(&bytes).ok();
    }
    HeaderValue::from_bytes(value.as_bytes()).ok()
}

fn extract_user_meta(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if let Some(rest) = name.strip_prefix("x-amz-meta-") {
            m.insert(rest.to_string(), header_value_string(v));
        }
    }
    m
}

fn put_object_opts(
    headers: &HeaderMap,
    owner: &crate::auth::StoredKey,
    default_object_acl: CannedAcl,
) -> PutObjectOpts {
    let header_value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };
    let content_encoding = header_value("content-encoding").and_then(|value| {
        let remaining = value
            .split(',')
            .map(str::trim)
            .filter(|encoding| !encoding.eq_ignore_ascii_case("aws-chunked"))
            .filter(|encoding| !encoding.is_empty())
            .collect::<Vec<_>>();
        (!remaining.is_empty()).then(|| remaining.join(", "))
    });
    let checksums = headers
        .iter()
        .filter_map(|(name, value)| {
            name.as_str()
                .strip_prefix("x-amz-checksum-")
                .and_then(|_| value.to_str().ok())
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    PutObjectOpts {
        content_type: header_value("content-type"),
        canned_acl: header_value("x-amz-acl").as_deref().and_then(CannedAcl::parse),
        acl: None,
        owner: owner.canonical_id.clone(),
        owner_display_name: owner.display_name.clone(),
        default_object_acl,
        user_meta: extract_user_meta(headers),
        content_encoding,
        cache_control: header_value("cache-control"),
        content_disposition: header_value("content-disposition"),
        content_language: header_value("content-language"),
        expires: header_value("expires"),
        checksums,
        sse_s3: false,
        sse_nonce: None,
        plaintext_size: None,
        etag_override: None,
    }
}

fn resolve_acl_from_request(
    headers: &HeaderMap,
    body: &Bytes,
    current: &AccessControlPolicy,
    _display: &str,
) -> Result<AccessControlPolicy, FlashError> {
    if let Some(canned) = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .and_then(CannedAcl::parse)
    {
        return Ok(AccessControlPolicy::from_canned(
            current.owner.clone(),
            &current.owner_display_name,
            canned,
        ));
    }
    // Grant headers
    if headers.keys().any(|k| k.as_str().starts_with("x-amz-grant-")) {
        let mut acl = AccessControlPolicy::from_canned(
            current.owner.clone(),
            &current.owner_display_name,
            CannedAcl::Private,
        );
        for (header_name, perm) in [
            ("x-amz-grant-read", Permission::Read),
            ("x-amz-grant-write", Permission::Write),
            ("x-amz-grant-read-acp", Permission::ReadAcp),
            ("x-amz-grant-write-acp", Permission::WriteAcp),
            ("x-amz-grant-full-control", Permission::FullControl),
        ] {
            if let Some(v) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
                for part in v.split(',') {
                    let part = part.trim();
                    if let Some(uri) = part.strip_prefix("uri=") {
                        let uri = uri.trim_matches('"');
                        if let Some(g) = flash_s3_common::GroupUri::parse(uri) {
                            acl.grants.push(flash_s3_common::Grant {
                                grantee: flash_s3_common::Grantee::Group { uri: g },
                                permission: perm,
                            });
                        }
                    } else if let Some(id) = part.strip_prefix("id=") {
                        let id = id.trim_matches('"');
                        acl.grants.push(flash_s3_common::Grant {
                            grantee: flash_s3_common::Grantee::CanonicalUser {
                                id: flash_s3_common::CanonicalUserId::new(id),
                                display_name: None,
                            },
                            permission: perm,
                        });
                    }
                }
            }
        }
        return Ok(acl);
    }
    if !body.is_empty() {
        let raw = std::str::from_utf8(body).map_err(|_| FlashError::MalformedAcl)?;
        return xml::parse_acl_xml(raw, current);
    }
    Err(FlashError::MalformedAcl)
}

/// MD5 ETag for plaintext (used for SSE-S3 overrides).
fn md5_etag_of(data: &[u8]) -> String {
    let mut h = md5::Md5::new();
    h.update(data);
    format!("\"{}\"", hex::encode(h.finalize()))
}

// silence unused ApiError
#[allow(dead_code)]
fn _api_err() -> ApiError {
    FlashError::Internal("x".into()).into()
}
