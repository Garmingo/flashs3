//! S3-compatible bucket CORS configuration.
//!
//! Stored per bucket and evaluated for browser preflight (`OPTIONS`) and
//! cross-origin `GET`/`PUT`/`HEAD`/`POST`/`DELETE` responses.
//!
//! JSON (camelCase) is used for bootstrap via `FLASHS3_DEFAULT_BUCKET_CORS` and
//! the operator CRD; the S3 wire format remains XML (`PutBucketCors`).

use serde::{Deserialize, Serialize};

use crate::FlashError;

/// Allowed HTTP methods in a CORS rule (S3 subset).
const ALLOWED_METHODS: &[&str] = &["GET", "PUT", "HEAD", "POST", "DELETE"];

/// Maximum CORS configuration document size (64 KiB, matching AWS S3).
pub const MAX_CORS_BYTES: usize = 64 * 1024;

/// Bucket CORS configuration (`PutBucketCors` / `GetBucketCors`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsConfiguration {
    /// Ordered rules; the first match wins (AWS behavior).
    pub rules: Vec<CorsRule>,
}

/// One CORS rule inside a [`CorsConfiguration`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsRule {
    /// Optional rule id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Origins allowed to make cross-origin requests (`*` or exact / wildcard).
    pub allowed_origins: Vec<String>,
    /// HTTP methods the origin may execute.
    pub allowed_methods: Vec<String>,
    /// Headers allowed in a preflight `Access-Control-Request-Headers` list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
    /// Response headers JavaScript may read (`Access-Control-Expose-Headers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_headers: Vec<String>,
    /// Browser cache lifetime for a successful preflight, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u32>,
}

impl CorsConfiguration {
    /// Permissive single-rule config for local/dev (`AllowedOrigin` / headers `*`).
    ///
    /// Allows `GET`/`PUT`/`HEAD`/`POST`/`DELETE` from any origin. Prefer explicit
    /// rules in production.
    pub fn allow_all() -> Self {
        Self {
            rules: vec![CorsRule {
                id: Some("allow-all".into()),
                allowed_origins: vec!["*".into()],
                allowed_methods: ALLOWED_METHODS
                    .iter()
                    .map(|method| (*method).to_string())
                    .collect(),
                allowed_headers: vec!["*".into()],
                expose_headers: vec![
                    "ETag".into(),
                    "x-amz-request-id".into(),
                    "x-amz-version-id".into(),
                    "x-amz-delete-marker".into(),
                ],
                max_age_seconds: Some(3600),
            }],
        }
    }

    /// Parse camelCase JSON (operator CRD / `FLASHS3_DEFAULT_BUCKET_CORS`).
    ///
    /// Accepts either `{"allowAll":true}` or `{"rules":[…]}` (not both).
    pub fn parse_json(raw: &str) -> Result<Self, FlashError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Bootstrap {
            #[serde(default)]
            allow_all: bool,
            #[serde(default)]
            rules: Vec<CorsRule>,
        }

        let boot: Bootstrap = serde_json::from_str(raw)
            .map_err(|_| FlashError::MalformedCORSConfiguration)?;
        if boot.allow_all {
            if !boot.rules.is_empty() {
                return Err(FlashError::InvalidRequest(
                    "cors allowAll cannot be combined with rules".into(),
                ));
            }
            return Ok(Self::allow_all());
        }

        let mut cors = Self { rules: boot.rules };
        for rule in &mut cors.rules {
            for method in &mut rule.allowed_methods {
                *method = method.to_ascii_uppercase();
            }
        }
        cors.validate()?;
        Ok(cors)
    }

    /// Serialize to camelCase JSON for env / CRD round-trips.
    pub fn to_json(&self) -> Result<String, FlashError> {
        serde_json::to_string(self).map_err(|e| FlashError::Internal(e.to_string()))
    }

    /// S3 `CORSConfiguration` XML body (GetBucketCors / on-disk `cors.xml`).
    pub fn to_xml(&self) -> String {
        let mut body = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
        );
        for rule in &self.rules {
            body.push_str("<CORSRule>");
            if let Some(id) = &rule.id {
                body.push_str(&format!("<ID>{}</ID>", xml_escape(id)));
            }
            for origin in &rule.allowed_origins {
                body.push_str(&format!(
                    "<AllowedOrigin>{}</AllowedOrigin>",
                    xml_escape(origin)
                ));
            }
            for method in &rule.allowed_methods {
                body.push_str(&format!(
                    "<AllowedMethod>{}</AllowedMethod>",
                    xml_escape(method)
                ));
            }
            for header in &rule.allowed_headers {
                body.push_str(&format!(
                    "<AllowedHeader>{}</AllowedHeader>",
                    xml_escape(header)
                ));
            }
            for header in &rule.expose_headers {
                body.push_str(&format!(
                    "<ExposeHeader>{}</ExposeHeader>",
                    xml_escape(header)
                ));
            }
            if let Some(max_age) = rule.max_age_seconds {
                body.push_str(&format!("<MaxAgeSeconds>{max_age}</MaxAgeSeconds>"));
            }
            body.push_str("</CORSRule>");
        }
        body.push_str("</CORSConfiguration>");
        body
    }

    /// Validate structural constraints after parsing.
    pub fn validate(&self) -> Result<(), FlashError> {
        if self.rules.is_empty() {
            return Err(FlashError::MalformedCORSConfiguration);
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }

    /// Find the first rule that matches an incoming browser request.
    ///
    /// For preflight, pass `Access-Control-Request-Method` as `method` and the
    /// `Access-Control-Request-Headers` value as `request_headers`. For actual
    /// requests, pass the HTTP method and an empty `request_headers` string.
    pub fn find_matching_rule<'a>(
        &'a self,
        origin: &str,
        method: &str,
        request_headers: &str,
    ) -> Option<&'a CorsRule> {
        self.rules
            .iter()
            .find(|rule| rule.matches(origin, method, request_headers))
    }
}

impl CorsRule {
    fn validate(&self) -> Result<(), FlashError> {
        if self.allowed_origins.is_empty() || self.allowed_methods.is_empty() {
            return Err(FlashError::MalformedCORSConfiguration);
        }
        for method in &self.allowed_methods {
            let upper = method.to_ascii_uppercase();
            if !ALLOWED_METHODS.contains(&upper.as_str()) {
                return Err(FlashError::InvalidRequest(format!(
                    "unsupported CORS AllowedMethod: {method}"
                )));
            }
        }
        Ok(())
    }

    /// Whether this rule matches the given Origin / method / requested headers.
    pub fn matches(&self, origin: &str, method: &str, request_headers: &str) -> bool {
        if !self.allowed_origins.iter().any(|o| origin_matches(o, origin)) {
            return false;
        }
        let method_upper = method.to_ascii_uppercase();
        if !self
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method_upper))
        {
            return false;
        }
        requested_headers_allowed(&self.allowed_headers, request_headers)
    }

    /// Value for `Access-Control-Allow-Origin` given the request Origin.
    pub fn allow_origin_value(&self, request_origin: &str) -> String {
        if self.allowed_origins.iter().any(|o| o == "*") {
            "*".into()
        } else {
            request_origin.to_string()
        }
    }
}

/// Match an AllowedOrigin pattern against a request Origin.
///
/// Supports exact match, `*`, and a single `*` wildcard (e.g. `https://*.example.com`).
pub fn origin_matches(allowed: &str, origin: &str) -> bool {
    if allowed == "*" || allowed == origin {
        return true;
    }
    if let Some((prefix, suffix)) = allowed.split_once('*') {
        if allowed.matches('*').count() != 1 {
            return false;
        }
        return origin.starts_with(prefix)
            && origin.ends_with(suffix)
            && origin.len() >= prefix.len() + suffix.len();
    }
    false
}

/// Whether every header in a comma-separated `Access-Control-Request-Headers`
/// list is covered by `allowed_headers` (`*` allows all).
pub fn requested_headers_allowed(allowed_headers: &[String], request_headers: &str) -> bool {
    let requested: Vec<&str> = request_headers
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();
    if requested.is_empty() {
        return true;
    }
    if allowed_headers.iter().any(|h| h == "*") {
        return true;
    }
    requested.iter().all(|req| {
        allowed_headers
            .iter()
            .any(|allowed| header_pattern_matches(allowed, req))
    })
}

fn header_pattern_matches(allowed: &str, requested: &str) -> bool {
    if allowed == "*" {
        return true;
    }
    if allowed.eq_ignore_ascii_case(requested) {
        return true;
    }
    // Single trailing/leading wildcard, e.g. `x-amz-*`
    if let Some((prefix, suffix)) = allowed.split_once('*') {
        if allowed.matches('*').count() != 1 {
            return false;
        }
        let req = requested.to_ascii_lowercase();
        let prefix = prefix.to_ascii_lowercase();
        let suffix = suffix.to_ascii_lowercase();
        return req.starts_with(&prefix)
            && req.ends_with(&suffix)
            && req.len() >= prefix.len() + suffix.len();
    }
    false
}

/// Filter requested headers down to those allowed by the rule (for
/// `Access-Control-Allow-Headers` on preflight responses).
pub fn allowed_request_headers(allowed_headers: &[String], request_headers: &str) -> Vec<String> {
    let requested: Vec<&str> = request_headers
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();
    if requested.is_empty() {
        return Vec::new();
    }
    if allowed_headers.iter().any(|h| h == "*") {
        return requested.into_iter().map(str::to_string).collect();
    }
    requested
        .into_iter()
        .filter(|req| {
            allowed_headers
                .iter()
                .any(|allowed| header_pattern_matches(allowed, req))
        })
        .map(str::to_string)
        .collect()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origins: &[&str], methods: &[&str], headers: &[&str]) -> CorsRule {
        CorsRule {
            id: None,
            allowed_origins: origins.iter().map(|s| (*s).to_string()).collect(),
            allowed_methods: methods.iter().map(|s| (*s).to_string()).collect(),
            allowed_headers: headers.iter().map(|s| (*s).to_string()).collect(),
            expose_headers: Vec::new(),
            max_age_seconds: Some(3000),
        }
    }

    #[test]
    fn matches_dev_origin_put_with_star_headers() {
        let cfg = CorsConfiguration {
            rules: vec![rule(
                &["http://localhost:3001"],
                &["PUT", "GET", "HEAD"],
                &["*"],
            )],
        };
        assert!(cfg
            .find_matching_rule(
                "http://localhost:3001",
                "PUT",
                "content-type,x-amz-acl"
            )
            .is_some());
        assert!(cfg
            .find_matching_rule("http://localhost:3000", "PUT", "content-type")
            .is_none());
        assert!(cfg
            .find_matching_rule("http://localhost:3001", "DELETE", "")
            .is_none());
    }

    #[test]
    fn star_origin_and_wildcard_subdomain() {
        assert!(origin_matches("*", "http://anywhere"));
        assert!(origin_matches(
            "https://*.example.com",
            "https://app.example.com"
        ));
        assert!(!origin_matches(
            "https://*.example.com",
            "https://example.com"
        ));
    }

    #[test]
    fn json_roundtrip_and_xml() {
        let raw = r#"{"rules":[{"allowedOrigins":["http://localhost:3001"],"allowedMethods":["put","GET"],"allowedHeaders":["*"],"maxAgeSeconds":3000}]}"#;
        let cfg = CorsConfiguration::parse_json(raw).unwrap();
        assert_eq!(cfg.rules[0].allowed_methods, vec!["PUT", "GET"]);
        let xml = cfg.to_xml();
        assert!(xml.contains("<AllowedOrigin>http://localhost:3001</AllowedOrigin>"));
        assert!(xml.contains("<AllowedMethod>PUT</AllowedMethod>"));
    }

    #[test]
    fn allow_all_json_and_helper() {
        let cfg = CorsConfiguration::parse_json(r#"{"allowAll":true}"#).unwrap();
        assert_eq!(cfg, CorsConfiguration::allow_all());
        assert!(cfg
            .find_matching_rule("http://anywhere:3000", "PUT", "content-type")
            .is_some());
        assert!(CorsConfiguration::parse_json(
            r#"{"allowAll":true,"rules":[{"allowedOrigins":["*"],"allowedMethods":["GET"]}]}"#
        )
        .is_err());
    }
}
