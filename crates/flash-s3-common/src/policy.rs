//! Minimal S3-compatible bucket policy model (JSON).
//!
//! Used for MinIO/Hetzner-style permission parity. Conditions are accepted in
//! the document but not fully evaluated yet (prefix/action/principal matching
//! is the MVP).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bucket policy document (`PutBucketPolicy` body).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BucketPolicy {
    /// Policy language version (default `2012-10-17`).
    #[serde(default = "default_version")]
    pub version: String,
    /// Optional policy id.
    #[serde(default)]
    pub id: Option<String>,
    /// Ordered statements; Deny wins over Allow when both match.
    pub statement: Vec<PolicyStatement>,
}

fn default_version() -> String {
    "2012-10-17".to_string()
}

/// One Allow/Deny statement inside a [`BucketPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatement {
    /// Optional statement id.
    #[serde(default)]
    pub sid: Option<String>,
    /// Allow or Deny.
    pub effect: PolicyEffect,
    /// Who the statement applies to (`*` or AWS principal map).
    pub principal: PolicyPrincipal,
    /// Action(s), e.g. `s3:GetObject` or `s3:*`.
    pub action: StringOrVec,
    /// Resource ARN(s), e.g. `arn:aws:s3:::bucket/*`.
    pub resource: StringOrVec,
    /// Optional condition block (parsed, not fully evaluated in MVP).
    #[serde(default)]
    pub condition: Option<Value>,
}

/// Statement effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyEffect {
    /// Explicit allow.
    Allow,
    /// Explicit deny (takes precedence).
    Deny,
}

/// Principal field: bare `"*"` or `{ "AWS": "…" }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyPrincipal {
    /// Typically `"*"`.
    Star(String),
    /// AWS-style principal map.
    Map {
        /// Access key, ARN, or `"*"`.
        #[serde(rename = "AWS")]
        aws: StringOrVec,
    },
}

impl PolicyPrincipal {
    /// Whether this principal matches the request's access key (if any).
    pub fn matches(&self, access_key: Option<&str>) -> bool {
        match self {
            Self::Star(s) => s == "*",
            Self::Map { aws } => aws.as_slice().into_iter().any(|p| {
                if p == "*" {
                    return true;
                }
                let Some(key) = access_key else {
                    return false;
                };
                if p == key {
                    return true;
                }
                // arn:flashs3:iam:::user/<accessKey> or arn:aws:iam:::user/...
                p.rsplit('/').next() == Some(key) || wildcard_match(p, key)
            }),
        }
    }
}

/// JSON field that may be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    /// Single value.
    One(String),
    /// Multiple values.
    Many(Vec<String>),
}

impl StringOrVec {
    /// Flatten to a list of string slices for matching.
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            Self::One(s) => vec![s.as_str()],
            Self::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }

    /// True if any pattern matches `value` with [`wildcard_match`].
    pub fn matches_any(&self, value: &str) -> bool {
        self.as_slice()
            .into_iter()
            .any(|p| wildcard_match(p, value))
    }
}

/// Simple `*` / `?` wildcard match used for Action/Resource/Principal.
pub fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut p = 0usize;
    let mut v = 0usize;
    let mut star_p = None;
    let mut star_v = 0usize;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v] || pattern[p] == b'?') {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = Some(p);
            star_v = v;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_v += 1;
            v = star_v;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Optional context for policy condition evaluation.
#[derive(Debug, Default)]
pub struct PolicyConditionCtx<'a> {
    /// Caller access key (maps to `aws:username`).
    pub access_key: Option<&'a str>,
    /// `s3:prefix` condition key value.
    pub s3_prefix: Option<&'a str>,
    /// `s3:delimiter` condition key value.
    pub s3_delimiter: Option<&'a str>,
    /// `s3:x-amz-acl` condition key value.
    pub s3_x_amz_acl: Option<&'a str>,
}

impl BucketPolicy {
    /// Parse policy JSON, tolerating lowercase field names.
    pub fn parse_json(raw: &str) -> Result<Self, crate::FlashError> {
        if let Ok(p) = serde_json::from_str::<Self>(raw) {
            return Ok(p);
        }
        let v: Value =
            serde_json::from_str(raw).map_err(|_| crate::FlashError::MalformedPolicy)?;
        let normalized = normalize_policy_json(v);
        serde_json::from_value(normalized).map_err(|_| crate::FlashError::MalformedPolicy)
    }

    /// Evaluate policy for an action/resource.
    ///
    /// Returns:
    /// - `Some(false)` if any matching statement Denies
    /// - `Some(true)` if at least one matching statement Allows (and none Deny)
    /// - `None` if no statement matched (caller falls through to ACLs)
    pub fn evaluate(
        &self,
        action: &str,
        resource: &str,
        access_key: Option<&str>,
        condition_ctx: Option<&PolicyConditionCtx<'_>>,
    ) -> Option<bool> {
        let mut denied = false;
        let mut allowed = false;
        for stmt in &self.statement {
            if !stmt.principal.matches(access_key) {
                continue;
            }
            if !stmt.action.matches_any(action) {
                continue;
            }
            if !stmt.resource.matches_any(resource) {
                continue;
            }
            if let Some(cond) = &stmt.condition {
                if !condition_matches(cond, condition_ctx) {
                    continue;
                }
            }
            match stmt.effect {
                PolicyEffect::Deny => denied = true,
                PolicyEffect::Allow => allowed = true,
            }
        }
        if denied {
            Some(false)
        } else if allowed {
            Some(true)
        } else {
            None
        }
    }
}

fn condition_matches(condition: &Value, ctx: Option<&PolicyConditionCtx<'_>>) -> bool {
    let Value::Object(operators) = condition else {
        return true;
    };
    let ctx_default = PolicyConditionCtx::default();
    let ctx = ctx.unwrap_or(&ctx_default);
    for (op_name, keys_obj) in operators {
        let Value::Object(keys) = keys_obj else {
            return false;
        };
        for (key, expected) in keys {
            let actual = resolve_condition_key(key, ctx);
            if !eval_condition_op(op_name, actual.as_deref(), expected) {
                return false;
            }
        }
    }
    true
}

fn resolve_condition_key<'a>(key: &str, ctx: &'a PolicyConditionCtx<'a>) -> Option<&'a str> {
    match key {
        "s3:prefix" => ctx.s3_prefix,
        "s3:delimiter" => ctx.s3_delimiter,
        "s3:x-amz-acl" => ctx.s3_x_amz_acl,
        "aws:username" => ctx.access_key,
        _ => None,
    }
}

fn eval_condition_op(op: &str, actual: Option<&str>, expected: &Value) -> bool {
    let expected_values = match expected {
        Value::String(s) => vec![s.as_str()],
        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => return false,
    };

    match op {
        "StringEquals" => {
            let Some(actual) = actual else { return false };
            expected_values.iter().any(|e| *e == actual)
        }
        "StringNotEquals" => {
            let Some(actual) = actual else { return true };
            expected_values.iter().all(|e| *e != actual)
        }
        "StringLike" => {
            let Some(actual) = actual else { return false };
            expected_values.iter().any(|e| wildcard_match(e, actual))
        }
        "StringNotLike" => {
            let Some(actual) = actual else { return true };
            expected_values.iter().all(|e| !wildcard_match(e, actual))
        }
        "Null" => {
            let check_null = expected_values
                .first()
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if check_null {
                actual.is_none()
            } else {
                actual.is_some()
            }
        }
        _ => false,
    }
}

/// Normalize common lowercase JSON keys to PascalCase for serde.
fn normalize_policy_json(mut v: Value) -> Value {
    if let Value::Object(map) = &mut v {
        rename_key(map, "version", "Version");
        rename_key(map, "id", "Id");
        rename_key(map, "statement", "Statement");
        if let Some(Value::Array(stmts)) = map.get_mut("Statement") {
            for s in stmts {
                if let Value::Object(sm) = s {
                    rename_key(sm, "sid", "Sid");
                    rename_key(sm, "effect", "Effect");
                    rename_key(sm, "principal", "Principal");
                    rename_key(sm, "action", "Action");
                    rename_key(sm, "resource", "Resource");
                    rename_key(sm, "condition", "Condition");
                    if let Some(Value::String(eff)) = sm.get_mut("Effect") {
                        if eff.eq_ignore_ascii_case("allow") {
                            *eff = "Allow".into();
                        } else if eff.eq_ignore_ascii_case("deny") {
                            *eff = "Deny".into();
                        }
                    }
                }
            }
        }
    }
    v
}

fn rename_key(map: &mut serde_json::Map<String, Value>, from: &str, to: &str) {
    if let Some(val) = map.remove(from) {
        map.insert(to.to_string(), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_basic() {
        assert!(wildcard_match("s3:Get*", "s3:GetObject"));
        assert!(wildcard_match("arn:aws:s3:::b/*", "arn:aws:s3:::b/foo"));
        assert!(!wildcard_match("s3:PutObject", "s3:GetObject"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("s3:GetObject", "s3:GetObject"));
    }

    #[test]
    fn parse_and_evaluate_allow() {
        let raw = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::demo/*"
            }]
        }"#;
        let p = BucketPolicy::parse_json(raw).unwrap();
        assert_eq!(
            p.evaluate("s3:GetObject", "arn:aws:s3:::demo/a.txt", None, None),
            Some(true)
        );
        assert_eq!(
            p.evaluate("s3:PutObject", "arn:aws:s3:::demo/a.txt", None, None),
            None
        );
    }

    #[test]
    fn deny_overrides_allow() {
        let raw = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": { "AWS": "*" },
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::demo/*"
                },
                {
                    "Effect": "Deny",
                    "Principal": { "AWS": "alice" },
                    "Action": "s3:DeleteObject",
                    "Resource": "arn:aws:s3:::demo/*"
                }
            ]
        }"#;
        let p = BucketPolicy::parse_json(raw).unwrap();
        assert_eq!(
            p.evaluate("s3:DeleteObject", "arn:aws:s3:::demo/x", Some("alice"), None),
            Some(false)
        );
        assert_eq!(
            p.evaluate("s3:GetObject", "arn:aws:s3:::demo/x", Some("alice"), None),
            Some(true)
        );
    }

    #[test]
    fn principal_arn_suffix_match() {
        let principal = PolicyPrincipal::Map {
            aws: StringOrVec::One("arn:flashs3:iam:::user/flash".into()),
        };
        assert!(principal.matches(Some("flash")));
        assert!(!principal.matches(Some("other")));
    }

    #[test]
    fn lowercase_json_normalized() {
        let raw = r#"{"version":"2012-10-17","statement":[{"effect":"allow","principal":"*","action":"s3:GetObject","resource":"arn:aws:s3:::b/*"}]}"#;
        let p = BucketPolicy::parse_json(raw).unwrap();
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::b/k", None, None), Some(true));
    }
}
