//! S3 POST object uploads (browser / presigned POST multipart form).

use std::collections::HashMap;

use axum::body::Body;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use flash_s3_common::{CannedAcl, FlashError, ObjectKey, Permission};
use futures::TryStreamExt;
use multer::Multipart;

use crate::api::xml;
use crate::auth::{
    resolve_post_object_key, verify_anonymous_post_allowed, verify_post_policy, AuthContext,
    PostFormFields,
};
use crate::server::AppState;
use crate::storage::PutObjectOpts;

/// Handle `POST /{bucket}` multipart form uploads.
pub async fn handle_post_object(
    state: AppState,
    bucket: String,
    headers: HeaderMap,
    body: Body,
    request_id: &str,
) -> Result<Response, FlashError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| FlashError::InvalidRequest("missing Content-Type".into()))?;
    let boundary = parse_boundary(content_type)
        .ok_or_else(|| FlashError::InvalidRequest("missing multipart boundary".into()))?;

    let stream = body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let mut multipart = Multipart::new(stream, boundary);

    let mut fields = PostFormFields::default();
    let mut file_name: Option<String> = None;
    let mut file_content_type: Option<String> = None;
    let mut file_bytes: Option<Bytes> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| FlashError::InvalidRequest(e.to_string()))?
    {
        let name = field
            .name()
            .ok_or_else(|| FlashError::InvalidRequest("unnamed form field".into()))?
            .to_string();
        let is_file_part = name.eq_ignore_ascii_case("file");
        if is_file_part {
            if file_name.is_none() {
                file_name = field.file_name().map(|s| s.to_string());
            }
            if file_content_type.is_none() {
                file_content_type = field.content_type().map(|m| m.to_string());
            }
            let data = field
                .bytes()
                .await
                .map_err(|e| FlashError::InvalidRequest(e.to_string()))?;
            file_bytes = Some(data);
        } else {
            let value = field
                .text()
                .await
                .map_err(|e| FlashError::InvalidRequest(e.to_string()))?;
            fields.insert(&name, value);
        }
    }

    let file_body = file_bytes.ok_or_else(|| FlashError::InvalidRequest("missing file".into()))?;
    let file_size = file_body.len() as u64;

    let resolved_key = resolve_post_object_key(&fields, file_name.as_deref())?;
    let mut verify_fields = fields.clone();
    verify_fields.insert("key", resolved_key.clone());

    let info = state.store.get_bucket(&bucket).await?;
    let policy_b64 = fields.raw_policy_b64().map(str::to_string);

    let ctx = if let Some(ref policy) = policy_b64 {
        let verified = verify_post_policy(
            &bucket,
            policy,
            &verify_fields,
            file_size,
            file_content_type.as_deref(),
            &state.config.region,
            &state.creds,
        )?;
        if let Some(key) = verified.key {
            AuthContext::authenticated(key)
        } else {
            AuthContext::anonymous()
        }
    } else {
        verify_anonymous_post_allowed(
            info.acl.allows(None, Permission::Write, false),
            false,
        )?;
        AuthContext::anonymous()
    };

    let key = ObjectKey::new(&resolved_key).map_err(|_| FlashError::InvalidObjectName)?;

    let owner = if let Some(ref k) = ctx.key {
        (k.canonical_id.clone(), k.display_name.clone())
    } else {
        (info.owner.clone(), info.owner_display_name.clone())
    };

    let mut user_meta = HashMap::new();
    for (name, value) in fields.iter() {
        if let Some(rest) = name.strip_prefix("x-amz-meta-") {
            user_meta.insert(rest.to_string(), value.to_string());
        }
    }

    let canned_acl = fields
        .get("acl")
        .and_then(CannedAcl::parse)
        .or_else(|| fields.get("x-amz-acl").and_then(CannedAcl::parse));

    let opts = PutObjectOpts {
        content_type: fields
            .get("content-type")
            .map(str::to_string)
            .or(file_content_type),
        canned_acl,
        acl: None,
        owner: owner.0,
        owner_display_name: owner.1,
        default_object_acl: info.default_object_acl,
        user_meta,
        content_encoding: None,
        cache_control: fields.get("cache-control").map(str::to_string),
        content_disposition: fields.get("content-disposition").map(str::to_string),
        content_language: fields.get("content-language").map(str::to_string),
        expires: fields.get("expires").map(str::to_string),
        checksums: HashMap::new(),
        sse_s3: false,
        sse_nonce: None,
        plaintext_size: None,
        etag_override: None,
    };

    let meta = state
        .store
        .put_object(&bucket, &key, file_body.clone(), opts)
        .await?;

    if meta.size <= state.cache.object_max_bytes() {
        state.cache.insert(&bucket, key.as_str(), file_body).await;
    }

    state
        .metrics
        .s3_requests
        .with_label_values(&["POST", "204", "PostObject"])
        .inc();

    build_post_success_response(
        &bucket,
        &resolved_key,
        &meta.etag,
        &fields,
        &state.config.bind,
        request_id,
    )
}

fn build_post_success_response(
    bucket: &str,
    key: &str,
    etag: &str,
    fields: &PostFormFields,
    bind: &str,
    request_id: &str,
) -> Result<Response, FlashError> {
    if let Some(redirect) = fields.get("success_action_redirect") {
        let bare_etag = etag.trim_matches('"');
        let location = format!(
            "{redirect}?bucket={bucket}&key={key}&etag=%22{bare_etag}%22"
        );
        return Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, location)
            .header("x-amz-request-id", request_id)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
    }

    let status_code = fields
        .get("success_action_status")
        .and_then(|s| s.parse::<u16>().ok());

    let status = match status_code {
        Some(201) => StatusCode::CREATED,
        Some(200) => StatusCode::OK,
        Some(404) | None | Some(_) => StatusCode::NO_CONTENT,
    };

    if matches!(status, StatusCode::OK | StatusCode::CREATED) {
        let host = bind.split(':').next().unwrap_or("localhost");
        let location = format!("http://{host}/{bucket}/{key}");
        let body = xml::post_response_xml(&location, bucket, key, etag);
        return Ok(Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/xml")
            .header("x-amz-request-id", request_id)
            .body(Body::from(body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
    }

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("x-amz-request-id", request_id)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

fn parse_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("boundary=") {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

/// True when this request should be handled as S3 POST object upload.
pub fn is_post_object_upload(
    method: &http::Method,
    has_object_key: bool,
    query: &std::collections::BTreeMap<String, String>,
    headers: &HeaderMap,
) -> bool {
    if *method != http::Method::POST || has_object_key || query.contains_key("delete") {
        return false;
    }
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("multipart/form-data"))
}