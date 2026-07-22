//! Path-style S3 request router and handlers.
//!
//! A single catch-all dispatches on HTTP method + query flags (`acl`, `policy`,
//! `uploads`, `uploadId`, …) to keep Axum routing simple while covering the
//! S3 API surface we implement.

use std::collections::BTreeMap;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use bytes::Bytes;
use chrono::DateTime;
use flash_s3_common::{
    AccessControlPolicy, CannedAcl, FlashError, ObjectKey, Permission,
};
use futures::{StreamExt, TryStreamExt};
use http_body_util::BodyExt;
use tokio::io::AsyncReadExt;
use tokio_util::io::{ReaderStream, StreamReader};
use tower_http::catch_panic::CatchPanicLayer;
use uuid::Uuid;

use crate::api::error::{s3_error_response, xml_escape, ApiError};
use crate::api::xml;
use crate::auth::{hash_payload, verify_request, AuthContext, S3Action};
use crate::server::AppState;
use crate::storage::PutObjectOpts;

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
    let result =
        dispatch_inner(state, method, uri, headers, req.into_body(), path, &request_id).await;
    match result {
        Ok(resp) => resp,
        Err(err) => s3_error_response(err, &resource, &request_id),
    }
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
    let has_object_key = path
        .as_deref()
        .map(|p| p.split('/').filter(|segment| !segment.is_empty()).count() > 1)
        .unwrap_or(false);
    let is_streaming_upload = method == Method::PUT
        && has_object_key
        && !headers.contains_key("x-amz-copy-source")
        && !query_map.contains_key("acl")
        && (query_map.contains_key("partNumber") || query_map.is_empty());

    if is_streaming_upload
        && (headers.contains_key("x-amz-content-sha256")
            || query_map.contains_key("X-Amz-Signature"))
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
        let path = path.ok_or_else(|| FlashError::InvalidRequest("missing path".into()))?;
        let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Err(FlashError::InvalidRequest("empty path".into()));
        }
        let bucket = segments.remove(0).to_string();
        let key_raw = segments.join("/");
        if key_raw.is_empty() {
            return Err(FlashError::InvalidRequest("missing object key".into()));
        }
        let key = ObjectKey::new(&key_raw).map_err(|_| FlashError::InvalidObjectName)?;
        let stream = TryStreamExt::map_err(body.into_data_stream(), std::io::Error::other);
        let reader = StreamReader::new(stream);
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

    let body_bytes = body
        .collect()
        .await
        .map_err(|e| FlashError::Internal(e.to_string()))?
        .to_bytes();

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

    // Require auth for mutating service ops when keys exist
    if path.is_none() && method == Method::GET {
        return list_buckets(&state, &ctx, request_id).await;
    }

    let path = path.ok_or_else(|| FlashError::InvalidRequest("missing path".into()))?;
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Err(FlashError::InvalidRequest("empty path".into()));
    }
    let bucket = segments.remove(0).to_string();
    let key_raw = if segments.is_empty() {
        None
    } else {
        Some(segments.join("/"))
    };

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
        Some(a) => AuthContext::authenticated(a.key),
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
    if query.contains_key("policy") {
        return bucket_policy_ops(state, ctx, method, bucket, body, request_id).await;
    }
    if query.contains_key("acl") {
        return bucket_acl_ops(state, ctx, method, bucket, body, headers, request_id).await;
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
        Method::GET => {
            let info = state.store.get_bucket(bucket).await?;
            let policy = state.store.load_policy(bucket).await?;
            state.authorizer.authorize(
                ctx,
                S3Action::ListBucket,
                Some(&info),
                None,
                policy.as_ref(),
            )?;
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let max_keys = query
                .get("max-keys")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000)
                .min(1000);
            let start_after = query
                .get("start-after")
                .or_else(|| query.get("continuation-token"))
                .map(|s| s.as_str());
            let (entries, truncated) =
                state
                    .store
                    .list_objects(bucket, &prefix, start_after, max_keys)?;
            let next = if truncated {
                entries.last().map(|e| e.key.as_str())
            } else {
                None
            };
            let body = xml::list_objects_v2_xml(
                bucket,
                &prefix,
                max_keys,
                truncated,
                &entries,
                next,
            );
            state.metrics.s3_requests.with_label_values(&["GET", "200", "ListObjectsV2"]).inc();
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
    // Multipart
    if query.contains_key("uploads") && *method == Method::POST {
        return create_multipart(state, ctx, bucket, key, headers, request_id).await;
    }
    if let Some(upload_id) = query.get("uploadId") {
        if query.contains_key("partNumber") && *method == Method::PUT {
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
        // public-read-write bucket ACL may allow
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
        // For overwrite, check object ACL if exists
        let obj = state.store.get_object_meta(bucket, key).await.ok();
        state.authorizer.authorize(
            ctx,
            S3Action::PutObject,
            Some(&info),
            obj.as_ref(),
            policy.as_ref(),
        )?;
    }

    let info = state.store.get_bucket(bucket).await?;
    let owner = ctx.key.as_ref().ok_or(FlashError::AccessDenied)?;
    let canned = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .and_then(CannedAcl::parse);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let opts = PutObjectOpts {
        content_type,
        canned_acl: canned,
        acl: None,
        owner: owner.canonical_id.clone(),
        owner_display_name: owner.display_name.clone(),
        default_object_acl: info.default_object_acl,
        user_meta: extract_user_meta(headers),
    };

    let meta = state
        .store
        .put_object(bucket, key, body.clone(), opts)
        .await?;

    if (meta.size) <= state.cache.object_max_bytes() {
        state.cache.insert(bucket, key.as_str(), body).await;
    } else {
        state.cache.invalidate(bucket, key.as_str()).await;
    }

    state.metrics.s3_requests.with_label_values(&["PUT", "200", "PutObject"]).inc();
    Ok(etag_ok(&meta.etag, request_id))
}

async fn put_object_stream(
    state: &AppState,
    ctx: &AuthContext,
    bucket: &str,
    key: &ObjectKey,
    reader: impl tokio::io::AsyncRead + Unpin,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Response, FlashError> {
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

    let owner = ctx.key.as_ref().ok_or(FlashError::AccessDenied)?;
    let canned = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .and_then(CannedAcl::parse);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let opts = PutObjectOpts {
        content_type,
        canned_acl: canned,
        acl: None,
        owner: owner.canonical_id.clone(),
        owner_display_name: owner.display_name.clone(),
        default_object_acl: info.default_object_acl,
        user_meta: extract_user_meta(headers),
    };
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

    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim_matches('"') == meta.etag.trim_matches('"') || inm == meta.etag {
            return Ok(StatusCode::NOT_MODIFIED.into_response());
        }
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
    let opts = PutObjectOpts {
        content_type: Some(src_meta.content_type.clone()),
        canned_acl: canned,
        acl: None,
        owner: owner.canonical_id.clone(),
        owner_display_name: owner.display_name.clone(),
        default_object_acl: dst_info.default_object_acl,
        user_meta: src_meta.user_meta.clone(),
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

fn extract_user_meta(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if let Some(rest) = name.strip_prefix("x-amz-meta-") {
            if let Ok(val) = v.to_str() {
                m.insert(rest.to_string(), val.to_string());
            }
        }
    }
    m
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

// silence unused ApiError
#[allow(dead_code)]
fn _api_err() -> ApiError {
    FlashError::Internal("x".into()).into()
}
