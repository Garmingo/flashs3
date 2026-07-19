//! S3 XML error responses and escaping helpers.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use flash_s3_common::FlashError;

/// Build a standard S3 `<Error>` XML response for `err`.
pub fn s3_error_response(err: FlashError, resource: &str, request_id: &str) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>{}</Code>
  <Message>{}</Message>
  <Resource>{}</Resource>
  <RequestId>{}</RequestId>
</Error>"#,
        err.code(),
        xml_escape(&err.to_string()),
        xml_escape(resource),
        xml_escape(request_id)
    );
    (
        status,
        [(header::CONTENT_TYPE, "application/xml")],
        body,
    )
        .into_response()
}

/// Escape XML special characters in element text.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Axum-friendly error wrapper (used sparingly; most handlers return `FlashError`).
pub struct ApiError {
    /// Underlying Flash/S3 error.
    pub err: FlashError,
    /// Request resource path for the XML body.
    pub resource: String,
    /// Correlation id echoed to the client.
    pub request_id: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        s3_error_response(self.err, &self.resource, &self.request_id)
    }
}

impl From<FlashError> for ApiError {
    fn from(err: FlashError) -> Self {
        Self {
            err,
            resource: "/".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}
